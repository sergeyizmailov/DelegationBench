"""Reference-defense tests: the delegation-envelope guard."""

import dataclasses
from pathlib import Path
from types import SimpleNamespace

import pytest

from delegationbench.cli import main
from delegationbench.clock import VirtualClock
from delegationbench.defense import DEFAULT_SIGNING_KEY, EnvelopeGuard
from delegationbench.envelope import Envelope
from delegationbench.oracle import evaluate
from delegationbench.report import build_report, defense_outcome
from delegationbench.runner import run_scenario
from delegationbench.scenario import load_scenario
from delegationbench.trace import BlockedError

ROOT = Path(__file__).resolve().parent.parent
ATTACKS_DIR = ROOT / "scenarios" / "attacks"
BENIGN_DIR = ROOT / "scenarios" / "benign"
SCENARIOS_DIR = ROOT / "scenarios"
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
