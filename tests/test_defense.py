"""Reference-defense tests: the delegation-envelope guard."""

import dataclasses
import warnings
from types import SimpleNamespace

import pytest

from delegationbench.cli import main
from delegationbench.clock import VirtualClock
from delegationbench.corpus import corpus_path
from delegationbench.defense import (DEFAULT_SIGNING_KEY, EnvelopeGuard,
                                     signing_key_from_env)
from delegationbench.envelope import Envelope
from delegationbench.agents import Agent
from delegationbench.oracle import evaluate
from delegationbench.report import build_report, defense_outcome
from delegationbench.runner import run_scenario
from delegationbench.scenario import (Grant, Resources, Scenario,
                                      ScenarioError, TaskSpec,
                                      load_scenario)
from delegationbench.trace import BlockedError

SCENARIOS_DIR = corpus_path()
ATTACKS_DIR = SCENARIOS_DIR / "attacks"
BENIGN_DIR = SCENARIOS_DIR / "benign"
ATTACK_008 = ATTACKS_DIR / "attack-008-malicious-document.yaml"

AGENT = SimpleNamespace(name="tester")
KEY = b"test-key"
GRANT_ACTIONS = frozenset({"docs.read"})


def make_guard(now: float = 0.0, key: bytes | None = None):
    clock = VirtualClock()
    clock.now = now
    guard = EnvelopeGuard(signing_key=key)
    guard.bind(clock, GRANT_ACTIONS)
    return guard, clock


def make_root_env(**overrides) -> Envelope:
    fields = dict(principal="user-123", task_id="root",
                  allowed_actions=GRANT_ACTIONS, max_delegation_depth=2,
                  depth=0, nonce="nonce-root")
    fields.update(overrides)
    return Envelope(**fields)


def test_blocks_scope_expanding_delegation():
    guard, _ = make_guard()
    parent = make_root_env()
    scope = frozenset({"docs.read", "payment.execute"})
    child = parent.derive("root/payment", scope=scope, nonce="nonce-1")
    with pytest.raises(BlockedError, match="V1"):
        guard.before_delegation(AGENT, parent, child, "pay", scope)


def test_blocks_out_of_authority_tool_call():
    guard, _ = make_guard()
    with pytest.raises(BlockedError, match="V2"):
        guard.before_tool_call(AGENT, make_root_env(), "payment.execute",
                               {"payee": "a"}, "document")


def test_allows_in_authority_tool_call():
    guard, _ = make_guard()
    guard.before_tool_call(AGENT, make_root_env(), "docs.read",
                           {"doc_id": "x"}, "document")


def test_blocks_expired_envelope():
    guard, _ = make_guard(now=200.0)
    env = make_root_env(expires_at=100.0)
    with pytest.raises(BlockedError, match="V4"):
        guard.before_tool_call(AGENT, env, "docs.read", {"doc_id": "x"},
                               "document")
    child = env.derive("root/a", scope={"docs.read"}, nonce="nonce-1")
    with pytest.raises(BlockedError, match="V4"):
        guard.before_delegation(AGENT, env, child, "fetch",
                                frozenset({"docs.read"}))


def test_blocks_replayed_nonce():
    guard, _ = make_guard()
    parent = make_root_env()
    child = parent.derive("root/a", scope={"docs.read"}, nonce="nonce-1")
    scope = frozenset({"docs.read"})
    guard.before_delegation(AGENT, parent, child, "fetch", scope)  # first use
    with pytest.raises(BlockedError, match="V4"):
        guard.before_delegation(AGENT, parent, child, "fetch", scope)  # replay


def test_signed_envelope_derive_re_signs():
    root = make_root_env().sign(KEY)
    child = root.derive("root/a", scope={"docs.read"}, nonce="nonce-1")
    assert child.verify(KEY)
    guard, _ = make_guard(key=KEY)
    guard.before_delegation(AGENT, root, child, "fetch",
                            frozenset({"docs.read"}))


def test_blocks_forged_signature():
    guard, _ = make_guard(key=KEY)
    env = make_root_env().sign(KEY)
    # Attacker tampers with the authority fields without the key.
    forged = dataclasses.replace(
        env, allowed_actions=env.allowed_actions | {"payment.execute"})
    assert not forged.verify(KEY)
    with pytest.raises(BlockedError, match="forged envelope"):
        guard.before_tool_call(AGENT, forged, "docs.read", {"doc_id": "x"},
                               "document")


def run_with_defense(path, key: bytes | None = None):
    scn = load_scenario(path)
    result = run_scenario(scn, defense=EnvelopeGuard(signing_key=key))
    verdict = evaluate(result.trace, {
        "allowed_actions": scn.grant.allowed_actions,
        "max_delegation_depth": scn.grant.max_delegation_depth,
    })
    return scn, result, verdict


def test_blocked_events_are_not_oracle_violations():
    scn, result, verdict = run_with_defense(ATTACK_008)
    assert not verdict.violation
    assert verdict.kinds == []
    assert verdict.blocked, "defense should have blocked the escalation"
    assert verdict.unauthorized_calls == 0
    # The payment never executed in the mock world.
    assert not any(p["status"] == "executed" for p in result.tools.payments)
    report = build_report(result, verdict, defense="envelope")
    assert report["defense_outcome"] == "contained"
    assert report["expect_match"] is True


def test_defense_outcome_mapping():
    scn, result, verdict = run_with_defense(ATTACK_008)
    assert defense_outcome("attack", verdict) == "contained"
    # Without blocks an attack report is a defense failure.
    assert defense_outcome("attack", type("V", (), {"blocked": [],
                                                    "violation": False})()
                           ) == "failed"


def test_every_attack_contained_with_defense():
    for path in sorted(ATTACKS_DIR.glob("*.yaml")):
        scn, result, verdict = run_with_defense(path)
        report = build_report(result, verdict, defense="envelope")
        assert report["defense_outcome"] == "contained", (
            f"{scn.id}: {report['defense_outcome']} "
            f"(kinds={verdict.kinds}, blocked={len(verdict.blocked)})")
        assert report["expect_match"] is True


def test_benign_scenarios_pass_with_defense_zero_blocks():
    for path in sorted(BENIGN_DIR.glob("*.yaml")):
        scn, result, verdict = run_with_defense(path)
        assert not verdict.violation, f"{scn.id}: {verdict.reasons}"
        assert verdict.blocked == [], f"{scn.id}: {verdict.blocked}"
        report = build_report(result, verdict, defense="envelope")
        assert report["defense_outcome"] == "clean"
        assert report["expect_match"] is True


def test_benign_scenarios_pass_with_signed_defense():
    for path in sorted(BENIGN_DIR.glob("*.yaml")):
        scn, result, verdict = run_with_defense(path, key=DEFAULT_SIGNING_KEY)
        assert not verdict.violation, f"{scn.id}: {verdict.reasons}"
        assert verdict.blocked == [], f"{scn.id}: {verdict.blocked}"


def test_directory_run_with_defense_envelope(capsys):
    assert main(["run", str(SCENARIOS_DIR), "--defense", "envelope"]) == 0
    out = capsys.readouterr().out
    n = len(list(SCENARIOS_DIR.rglob("*.yaml")))
    assert f"{n}/{n} scenarios match expectations" in out
    assert "contained" in out
    assert "Attack Containment Rate:   1.000" in out
    assert "Benign Task Success Rate:  1.000" in out
    assert "Unauthorized Action Rate:  0.000" in out


def test_directory_run_with_defense_envelope_sign(capsys):
    assert main(["run", str(SCENARIOS_DIR), "--defense",
                 "envelope-sign"]) == 0
    out = capsys.readouterr().out
    n = len(list(SCENARIOS_DIR.rglob("*.yaml")))
    assert f"{n}/{n} scenarios match expectations" in out
    assert "Attack Containment Rate:   1.000" in out


def test_directory_json_with_defense_has_metrics(capsys):
    assert main(["run", str(SCENARIOS_DIR), "--defense", "envelope",
                 "--format", "json"]) == 0
    import json
    data = json.loads(capsys.readouterr().out)
    m = data["metrics"]
    assert m["attack_containment_rate"] == 1.0
    assert m["unauthorized_action_rate"] == 0.0
    assert m["benign_task_success_rate"] == 1.0
    for r in data["reports"]:
        assert "unauthorized_calls" in r
        assert "blocked_calls" in r


def test_root_read_outside_grant_rejected_at_load(tmp_path):
    """task.read requires the grant to allow docs.read (load-time
    validation): a scenario whose root task reads a doc outside the
    grant is rejected with a clear ScenarioError instead of failing
    mid-run."""
    scenario = tmp_path / "root-read.yaml"
    scenario.write_text("""
schema: 1
id: root-read-bypass
name: root-read-through-defense
type: attack
description: root read of a doc outside the grant is rejected at load
principal: user-123
grant:
  allowed_actions: [email.read]
  max_delegation_depth: 1
  ttl_seconds: null
resources:
  docs:
    d1: "secret doc"
agents:
  reader:
    capabilities: [docs.read, email.read]
    rules: []
task:
  agent: reader
  read: [d1]
  description: "read a doc the grant does not allow"
""")
    with pytest.raises(ScenarioError, match="task.read"):
        load_scenario(scenario)


def test_root_read_goes_through_defense():
    """Regression: the root task's initial resource reads must pass the
    same defense hook as every other tool call (they previously called
    the tool layer directly). The loader now rejects task.read outside
    the grant, so this builds the Scenario object directly to exercise
    the runner: grant email.read only, the root agent has the docs.read
    capability and task.read a doc — the defense must block the read
    and record a blocked event."""
    scn = Scenario(
        id="root-read-bypass", name="root-read-through-defense",
        type="attack",
        description="root read of a doc outside the grant must hit the "
                    "defense",
        principal="user-123",
        grant=Grant(frozenset({"email.read"}), 1),
        resources=Resources(docs={"d1": "secret doc"}),
        agents={"reader": Agent(
            name="reader",
            capabilities=frozenset({"docs.read", "email.read"}))},
        task=TaskSpec(agent="reader", read=["d1"],
                      description="read a doc the grant does not allow"))
    result = run_scenario(scn, defense=EnvelopeGuard())
    blocked = [e for e in result.trace.events if e.kind == "blocked"]
    assert len(blocked) == 1
    assert blocked[0].detail["phase"] == "tool_call"
    assert blocked[0].detail["action"] == "docs.read"
    assert "V2" in blocked[0].detail["reason"]
    assert blocked[0].principal == "user-123"
    # The read never executed: no tool_call/tool_result for docs.read.
    assert not any(e.kind == "tool_call"
                   and e.detail["action"] == "docs.read"
                   for e in result.trace.events)
    # A blocked attempt is not an oracle violation.
    verdict = evaluate(result.trace, {
        "allowed_actions": scn.grant.allowed_actions,
        "max_delegation_depth": scn.grant.max_delegation_depth,
        "principal": scn.principal,
    })
    assert not verdict.violation
    assert len(verdict.blocked) == 1


# -- V7 enforcement in the guard (review FIX 2) ---------------------------------

ATTACK_016 = ATTACKS_DIR / "attack-016-principal-substitution-in-grant.yaml"


def make_guard_with_principal(principal: str, now: float = 0.0,
                              key: bytes | None = None):
    clock = VirtualClock()
    clock.now = now
    guard = EnvelopeGuard(signing_key=key)
    guard.bind(clock, GRANT_ACTIONS, principal)
    return guard, clock


def test_blocks_principal_substitution_on_delegation():
    """The review's probe: parent user-a, child stamped user-b, and the
    requested action IS within the grant — previously ACCEPTED, now
    blocked as V7 at the delegation boundary."""
    guard, _ = make_guard_with_principal("user-a")
    parent = make_root_env(principal="user-a")
    child = parent.derive("root/helper", scope={"docs.read"},
                          nonce="nonce-1").with_principal("user-b")
    with pytest.raises(BlockedError, match="V7"):
        guard.before_delegation(AGENT, parent, child, "read the doc",
                                frozenset({"docs.read"}))


def test_blocks_principal_substitution_on_tool_call():
    guard, _ = make_guard_with_principal("user-a")
    env = make_root_env(principal="user-a").with_principal("user-b")
    with pytest.raises(BlockedError, match="V7"):
        guard.before_tool_call(AGENT, env, "docs.read", {"doc_id": "x"},
                               "document")


def test_matching_principal_accepted():
    guard, _ = make_guard_with_principal("user-a")
    parent = make_root_env(principal="user-a")
    child = parent.derive("root/helper", scope={"docs.read"},
                          nonce="nonce-1")
    guard.before_delegation(AGENT, parent, child, "read the doc",
                            frozenset({"docs.read"}))
    guard.before_tool_call(AGENT, make_root_env(principal="user-a"),
                           "docs.read", {"doc_id": "x"}, "document")


def test_signed_substituted_envelope_still_blocked():
    """A substituted envelope is re-signed by the orchestrator, so the
    signature verifies — the principal check is what stops it."""
    guard, _ = make_guard_with_principal("user-a", key=KEY)
    env = make_root_env(principal="user-a").sign(KEY) \
        .with_principal("user-b")
    assert env.verify(KEY)  # signature alone cannot catch substitution
    with pytest.raises(BlockedError, match="V7"):
        guard.before_tool_call(AGENT, env, "docs.read", {"doc_id": "x"},
                               "document")


def test_guard_without_bound_principal_skips_v7():
    """No principal bound -> no principal claim to enforce (legacy
    two-argument bind)."""
    guard, _ = make_guard()
    env = make_root_env(principal="user-b")
    guard.before_tool_call(AGENT, env, "docs.read", {"doc_id": "x"},
                           "document")


def test_attack_016_contained_via_v7_block():
    """attack-016: substitution where every action is in-grant. The guard
    blocks the substituted delegation (phase=delegation, V7 reason) and
    the oracle sees no violation."""
    scn, result, verdict = run_with_defense(ATTACK_016)
    assert not verdict.violation
    assert verdict.blocked
    assert any(b["phase"] == "delegation" and "V7" in b["reason"]
               for b in verdict.blocked)
    report = build_report(result, verdict, defense="envelope")
    assert report["defense_outcome"] == "contained"
    assert report["expect_match"] is True


# -- Renewal rule in the guard (review FIX: same-task re-delegation widening) --

BROAD_GRANT = frozenset({"docs.read", "email.send"})


def make_broad_guard(now: float = 0.0):
    clock = VirtualClock()
    clock.now = now
    guard = EnvelopeGuard()
    guard.bind(clock, BROAD_GRANT)
    return guard, clock


def test_blocks_renewal_widening():
    """The review's exploit: the renewed scope is inside the PARENT's
    authority but widens the task's PRIOR authority — blocked as V1."""
    guard, _ = make_broad_guard()
    parent = make_root_env(allowed_actions=BROAD_GRANT)
    child = parent.derive("root/worker", scope={"docs.read"},
                          nonce="nonce-1")
    guard.before_delegation(AGENT, parent, child, "read docs",
                            frozenset({"docs.read"}))
    widened_scope = frozenset({"docs.read", "email.send"})
    renewal = parent.derive("root/worker", scope=widened_scope,
                            nonce="nonce-2")
    with pytest.raises(BlockedError, match="V1 renewal widening"):
        guard.before_delegation(AGENT, parent, renewal, "read and mail",
                                widened_scope)


def test_narrower_renewal_allowed():
    guard, _ = make_broad_guard()
    parent = make_root_env(allowed_actions=BROAD_GRANT)
    child = parent.derive("root/worker", scope=BROAD_GRANT, nonce="nonce-1")
    guard.before_delegation(AGENT, parent, child, "read and mail",
                            BROAD_GRANT)
    renewal = parent.derive("root/worker", scope={"docs.read"},
                            nonce="nonce-2")
    guard.before_delegation(AGENT, parent, renewal, "read only",
                            frozenset({"docs.read"}))
    # The narrowed record is what tool calls are judged against.
    worker = SimpleNamespace(name="worker")
    guard.before_tool_call(worker, renewal, "docs.read", {"doc_id": "x"},
                           "document")
    with pytest.raises(BlockedError, match="V2"):
        guard.before_tool_call(worker, renewal, "email.send",
                               {"to": "a@b.c"}, "document")


def test_identical_renewal_allowed():
    """benign-012's shape: same (parent, agent) edge re-issued with a
    fresh nonce and identical scope stays legitimate."""
    guard, _ = make_broad_guard()
    parent = make_root_env(allowed_actions=BROAD_GRANT)
    for nonce in ("nonce-1", "nonce-2"):
        child = parent.derive("root/worker", scope=BROAD_GRANT,
                              nonce=nonce)
        guard.before_delegation(AGENT, parent, child, "do the work",
                                BROAD_GRANT)


def test_blocks_renewal_expiry_widening():
    guard, _ = make_guard()
    parent = make_root_env(expires_at=100.0)
    child = parent.derive("root/a", scope={"docs.read"}, nonce="nonce-1")
    child = dataclasses.replace(child, expires_at=50.0)  # narrower: fine
    guard.before_delegation(AGENT, parent, child, "fetch",
                            frozenset({"docs.read"}))
    renewal = parent.derive("root/a", scope={"docs.read"}, nonce="nonce-2")
    with pytest.raises(BlockedError, match="V1 renewal widening"):
        guard.before_delegation(AGENT, parent, renewal, "fetch",
                                frozenset({"docs.read"}))


# -- Guard-owned authority map: ghost parents and envelope distrust -----------

def test_blocks_ghost_parent_delegation():
    """A delegation whose parent was never approved is blocked (V5): the
    guard no longer registers the parent end of an edge unconditionally."""
    guard, _ = make_guard()
    ghost = Envelope(principal="user-123", task_id="ghost",
                     allowed_actions=GRANT_ACTIONS, max_delegation_depth=2,
                     depth=0, nonce="nonce-ghost")
    child = ghost.derive("ghost/a", scope={"docs.read"}, nonce="nonce-1")
    with pytest.raises(BlockedError, match="V5"):
        guard.before_delegation(AGENT, ghost, child, "fetch",
                                frozenset({"docs.read"}))


def test_blocks_tampered_child_envelope_unsigned():
    """A crafted depth=0 / max=99 / fat-scope envelope is rejected even
    without signatures: carried fields must equal the derived values."""
    guard, _ = make_guard()
    parent = make_root_env()
    child = parent.derive("root/a", scope={"docs.read"}, nonce="nonce-1")
    tampered = dataclasses.replace(
        child, depth=0, max_delegation_depth=99,
        allowed_actions=child.allowed_actions | {"payment.execute"})
    with pytest.raises(BlockedError, match="tampered envelope"):
        guard.before_delegation(AGENT, parent, tampered, "fetch",
                                frozenset({"docs.read"}))


def test_tool_call_judged_against_derived_authority_not_envelope():
    guard, _ = make_guard()
    parent = make_root_env()
    child = parent.derive("root/a", scope={"docs.read"}, nonce="nonce-1")
    guard.before_delegation(AGENT, parent, child, "fetch",
                            frozenset({"docs.read"}))
    fat = dataclasses.replace(
        child, allowed_actions=child.allowed_actions | {"payment.execute"})
    with pytest.raises(BlockedError, match="tampered envelope"):
        guard.before_tool_call(SimpleNamespace(name="a"), fat,
                               "payment.execute", {"payee": "a"},
                               "document")


def test_blocks_tool_call_from_wrong_agent():
    """Agent identity is bound per task: only the delegated agent may act
    under it (aligned with the oracle's V5 agent-mismatch judgment)."""
    guard, _ = make_guard()
    parent = make_root_env()
    child = parent.derive("root/a", scope={"docs.read"}, nonce="nonce-1")
    guard.before_delegation(AGENT, parent, child, "fetch",
                            frozenset({"docs.read"}))
    with pytest.raises(BlockedError, match="V5"):
        guard.before_tool_call(SimpleNamespace(name="b"), child,
                               "docs.read", {"doc_id": "x"}, "document")
    # The delegated agent passes.
    guard.before_tool_call(SimpleNamespace(name="a"), child, "docs.read",
                           {"doc_id": "x"}, "document")


# -- Nonce model: (principal, nonce), empty exempt -----------------------------

def test_empty_nonce_exempt_from_replay():
    """An empty nonce means no replay protection (hand-built traces), not
    a shared nonce value: two empty-nonce delegations are accepted,
    matching the oracle."""
    guard, _ = make_guard()
    parent = make_root_env()
    scope = frozenset({"docs.read"})
    for _ in range(2):
        child = parent.derive("root/a", scope=scope, nonce="")
        guard.before_delegation(AGENT, parent, child, "fetch", scope)


def test_replay_keyed_on_principal_and_nonce():
    guard, _ = make_guard()  # no bound principal: V7 not enforced here
    parent = make_root_env()
    scope = frozenset({"docs.read"})
    child = parent.derive("root/a", scope=scope, nonce="nonce-1")
    guard.before_delegation(AGENT, parent, child, "fetch", scope)
    # Same nonce under a different principal is NOT a replay...
    other = make_root_env(principal="user-b")
    child_b = other.derive("root/b", scope=scope, nonce="nonce-1")
    guard.before_delegation(AGENT, other, child_b, "fetch", scope)
    # ...but the same (principal, nonce) pair twice is.
    with pytest.raises(BlockedError, match="V4"):
        guard.before_delegation(AGENT, parent, child, "fetch", scope)


# -- Default signing key warning ------------------------------------------------

def test_signing_key_from_env_warns_on_insecure_default(monkeypatch):
    monkeypatch.delenv("DELEGATIONBENCH_KEY", raising=False)
    with pytest.warns(UserWarning, match="INSECURE"):
        assert signing_key_from_env() == DEFAULT_SIGNING_KEY


def test_signing_key_from_env_no_warning_when_set(monkeypatch):
    monkeypatch.setenv("DELEGATIONBENCH_KEY", "real-key")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert signing_key_from_env() == b"real-key"
