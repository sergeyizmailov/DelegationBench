"""Fuzzer tests: determinism, mutation operators, end-to-end campaign,
minimizer and regression generation."""

import copy
import json
import random
import re
from pathlib import Path

import pytest
import yaml

from delegationbench import fuzzer
from delegationbench.cli import main
from delegationbench.fuzzer import (BYPASS_COMMENT, OPERATORS,
                                    MutationNotApplicable, build_regression,
                                    classify, judge, judge_with_trace,
                                    minimize_finding, run_campaign)
from delegationbench.scenario import load_scenario, parse_scenario

ROOT = Path(__file__).resolve().parent.parent
ATTACK = ROOT / "scenarios" / "attacks" / "attack-008-malicious-document.yaml"
SEED_DATA = yaml.safe_load(ATTACK.read_text(encoding="utf-8"))
ATTACK_DIR = ROOT / "scenarios" / "attacks"
# Under the fixed classifier (dead mutants are not divergent), this
# seed/budget yields at least one genuine divergent finding.
DIVERGENT_ATTACK = ATTACK_DIR / "attack-009-replayed-delegation.yaml"


def _campaign(out, **kw):
    args = dict(budget=25, seed=7, defense="envelope", out=out)
    args.update(kw)
    return run_campaign(ATTACK, **args)


def _findings_key(report):
    """Findings with output paths stripped, for cross-directory comparison."""
    return [{k: v for k, v in f.items()
             if k not in ("mutant", "minimized", "regression")}
            for f in report["findings"]]


# -- determinism ------------------------------------------------------------


def test_campaign_determinism(tmp_path):
    r1 = _campaign(tmp_path / "a")
    r2 = _campaign(tmp_path / "b")
    assert _findings_key(r1) == _findings_key(r2)
    for key in ("mutants_run", "valid", "invalid", "duplicates", "counts"):
        assert r1[key] == r2[key], key


def test_cli_fuzz_twice_identical_findings(tmp_path, capsys):
    for name in ("a", "b"):
        assert main(["fuzz", str(ATTACK), "--budget", "25", "--seed", "7",
                     "--defense", "envelope",
                     "--out", str(tmp_path / name)]) == 0
        capsys.readouterr()
    c1 = json.loads((tmp_path / "a" / "campaign.json").read_text())
    c2 = json.loads((tmp_path / "b" / "campaign.json").read_text())
    assert _findings_key(c1) == _findings_key(c2)
    assert c1["counts"] == c2["counts"]


# -- mutation operators -------------------------------------------------------


@pytest.mark.parametrize("op_name", sorted(OPERATORS))
def test_operator_produces_loadable_mutant_or_clean_rejection(op_name):
    op = OPERATORS[op_name]
    outcomes = set()
    for seed in range(10):
        data = copy.deepcopy(SEED_DATA)
        try:
            op(data, random.Random(seed))
        except MutationNotApplicable:
            outcomes.add("rejected")
            continue
        parse_scenario(data, source=f"<{op_name}>")   # raises if invalid
        outcomes.add("valid")
    assert outcomes, "operator never produced an outcome"


def test_generate_mutant_is_deterministic():
    d1, ops1 = fuzzer.generate_mutant(SEED_DATA, random.Random(42))
    d2, ops2 = fuzzer.generate_mutant(SEED_DATA, random.Random(42))
    assert ops1 == ops2
    assert yaml.safe_dump(d1, sort_keys=True) == yaml.safe_dump(d2, sort_keys=True)


def test_generate_mutant_does_not_touch_seed():
    before = copy.deepcopy(SEED_DATA)
    fuzzer.generate_mutant(SEED_DATA, random.Random(1))
    assert SEED_DATA == before


# -- end-to-end on attack-008 -------------------------------------------------


def test_end_to_end_envelope_campaign(tmp_path):
    report = _campaign(tmp_path / "out", budget=30)
    campaign = json.loads((tmp_path / "out" / "campaign.json").read_text())
    assert campaign["seed"]["id"] == "attack-008"
    assert campaign["defense"] == "envelope"
    assert campaign["budget"] == 30
    assert campaign["random_seed"] == 7
    n = campaign["mutants_run"]
    assert campaign["valid"] + campaign["invalid"] \
        + campaign["duplicates"] + campaign["errors"] == n
    counts = campaign["counts"]
    assert counts["bypass"] + counts["divergent"] + counts["neutral"] \
        + counts["dead"] == campaign["valid"]
    assert len(campaign["findings"]) == counts["bypass"] + counts["divergent"]
    for finding in campaign["findings"]:
        assert finding["class"] in ("bypass", "divergent")
        for key in ("mutant", "minimized", "regression"):
            assert finding[key] is None or Path(finding[key]).is_file()
    assert report["wall_time_seconds"] >= 0


# -- minimizer + regressions ---------------------------------------------------


def _divergent_campaign(tmp_path):
    # Fixed seed/budget verified to yield at least one divergent finding
    # under the fixed classifier (a replay toggle defuses the V4 attack
    # while execution continues and the payload stays attack-shaped).
    return run_campaign(DIVERGENT_ATTACK, budget=60, seed=1, defense="none",
                        out=tmp_path / "out")


def test_divergent_findings_exist(tmp_path):
    report = _divergent_campaign(tmp_path)
    assert report["counts"]["divergent"] >= 1


def test_minimizer_preserves_finding_class(tmp_path):
    report = _divergent_campaign(tmp_path)
    finding = next(f for f in report["findings"]
                   if f["class"] == "divergent")
    min_scn = load_scenario(finding["minimized"])
    min_data = yaml.safe_load(Path(finding["minimized"]).read_text())
    seed = load_scenario(DIVERGENT_ATTACK)
    verdict, trace = judge_with_trace(min_scn, "none")
    assert classify(seed, min_data, verdict, "none", trace) == "divergent"


def test_regression_expect_matches_no_defense_run(tmp_path):
    report = _divergent_campaign(tmp_path)
    finding = report["findings"][0]
    reg_path = Path(finding["regression"])
    reg_scn = load_scenario(reg_path)
    verdict = judge(reg_scn, "none")
    assert reg_scn.expect is not None
    assert (reg_scn.expect.verdict == "violation") == verdict.violation
    assert set(reg_scn.expect.violation_kinds) <= set(verdict.kinds)
    assert set(reg_scn.expect.unauthorized_actions) \
        <= set(verdict.unauthorized_actions)


def test_regression_directory_passes_cli_run(tmp_path, capsys):
    _divergent_campaign(tmp_path)
    reg_dir = tmp_path / "out" / "regressions"
    assert main(["run", str(reg_dir)]) == 0
    capsys.readouterr()


def test_bypass_regression_carries_defense_comment():
    # attack-008 itself violates with no defense; a bypass-class regression
    # must record the no-defense verdict plus the defense-improvement note.
    reg, comment = build_regression(copy.deepcopy(SEED_DATA), "bypass")
    assert comment == BYPASS_COMMENT
    assert reg["expect"]["verdict"] == "violation"
    assert set(reg["expect"]["violation_kinds"]) >= {"V1", "V2"}
    assert "payment.execute" in reg["expect"]["unauthorized_actions"]


def test_minimize_finding_bounds_runs():
    seed = load_scenario(ATTACK)
    out = minimize_finding(copy.deepcopy(SEED_DATA), "divergent", "none",
                           seed, max_runs=5)
    parse_scenario(out, source="<bounded>")


# -- integrity-focused operators ----------------------------------------------

ATTACK_004 = yaml.safe_load(
    (ATTACK_DIR / "attack-004-orchestrator-bypass.yaml").read_text())
ATTACK_011 = yaml.safe_load(
    (ATTACK_DIR / "attack-011-cross-user-contamination.yaml").read_text())


def _tool_bodies(data):
    return [rule["then"]["tool"]
            for spec in data["agents"].values()
            for rule in spec.get("rules") or []
            if isinstance((rule.get("then") or {}).get("tool"), dict)]


def _delegate_bodies(data):
    return [rule["then"]["delegate"]
            for spec in data["agents"].values()
            for rule in spec.get("rules") or []
            if isinstance((rule.get("then") or {}).get("delegate"), dict)]


def test_principal_substitution_stamps_foreign_or_captured_principal():
    op = OPERATORS["principal_substitution"]
    stamped = set()
    for seed in range(20):
        data = copy.deepcopy(SEED_DATA)
        op(data, random.Random(seed))
        parse_scenario(data, source="<principal_substitution>")
        bodies = _delegate_bodies(data) + _tool_bodies(data)
        new = [b["as_principal"] for b in bodies
               if b.get("as_principal") is not None]
        assert new, "operator did not stamp as_principal"
        for value in new:
            assert value != data["principal"]
            stamped.add(value)
    # Both literal identities and content-derived ${capture} templates occur.
    assert any(not v.startswith("${") for v in stamped)
    assert any(v.startswith("${") for v in stamped)


def test_principal_substitution_not_applicable_to_untracked_only_seed():
    # attack-004's only tool rule is untracked (no envelope to re-stamp)
    # and it has no delegation rule: the operator must reject cleanly.
    with pytest.raises(MutationNotApplicable):
        OPERATORS["principal_substitution"](copy.deepcopy(ATTACK_004),
                                            random.Random(0))


def test_untracked_inject_sets_untracked_and_drops_as_principal():
    op = OPERATORS["untracked_inject"]
    for seed in range(10):
        data = copy.deepcopy(SEED_DATA)
        op(data, random.Random(seed))
        parse_scenario(data, source="<untracked_inject>")
        bodies = _tool_bodies(data)
        assert any(b.get("untracked") for b in bodies)
        for b in bodies:
            # schema: untracked and as_principal are mutually exclusive
            assert not (b.get("untracked") and b.get("as_principal"))


def test_untracked_inject_retracks_when_all_untracked():
    data = copy.deepcopy(ATTACK_004)   # sole tool rule is untracked
    OPERATORS["untracked_inject"](data, random.Random(0))
    parse_scenario(data, source="<untracked_inject>")
    assert not any(b.get("untracked") for b in _tool_bodies(data))


def test_identity_renaming_stays_consistent_and_loadable():
    op = OPERATORS["identity_renaming"]
    renamed_kinds = set()
    for seed in range(30):
        data = copy.deepcopy(ATTACK_011)
        before_agents = set(data["agents"])
        before_ids = set(data["resources"]["docs"]) \
            | set(data["resources"]["emails"])
        op(data, random.Random(seed))
        scn = parse_scenario(data, source="<identity_renaming>")
        after_agents = set(data["agents"])
        after_ids = set(data["resources"]["docs"]) \
            | set(data["resources"]["emails"])
        if after_agents != before_agents:
            renamed_kinds.add("agent")
            gone = before_agents - after_agents
            # no dangling reference to the old id anywhere structural
            assert scn.task.agent not in gone
            for body in _delegate_bodies(data):
                assert str(body.get("agent")) not in gone
        elif after_ids != before_ids:
            renamed_kinds.add("resource")
            gone = before_ids - after_ids
            assert not (set(data["task"]["read"]) & gone)
            for store in ("docs", "emails"):
                for text in data["resources"][store].values():
                    for old in gone:
                        # the new id embeds the old as a prefix; match the
                        # old id as a standalone token only
                        assert not re.search(
                            rf"(?<![\w-]){re.escape(old)}(?![\w-])",
                            str(text))
    assert renamed_kinds == {"agent", "resource"}


def test_envelope_tamper_coarser_than_grant_tweak():
    op = OPERATORS["envelope_tamper"]
    seen = set()
    base_ttl = SEED_DATA["grant"]["ttl_seconds"]
    base_depth = SEED_DATA["grant"]["max_delegation_depth"]
    for seed in range(30):
        data = copy.deepcopy(SEED_DATA)
        op(data, random.Random(seed))
        parse_scenario(data, source="<envelope_tamper>")
        g = data["grant"]
        if g["ttl_seconds"] is None:
            seen.add("ttl_remove")
        elif g["ttl_seconds"] != base_ttl:
            assert g["ttl_seconds"] >= base_ttl * 4
            seen.add("ttl_extend")
        if g["max_delegation_depth"] != base_depth:
            assert g["max_delegation_depth"] >= base_depth + 2
            seen.add("depth_jump")
        clocks = [rule.get("advance_clock")
                  for spec in data["agents"].values()
                  for rule in spec.get("rules") or []]
        if any(c for c in clocks):
            seen.add("clock_skip")
    assert {"ttl_remove", "ttl_extend", "depth_jump", "clock_skip"} <= seen


def test_new_operators_loadable_or_rejected_on_every_attack_seed():
    for path in sorted(ATTACK_DIR.glob("*.yaml")):
        seed_data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name in ("principal_substitution", "untracked_inject",
                     "identity_renaming", "envelope_tamper"):
            op = OPERATORS[name]
            for seed in range(5):
                data = copy.deepcopy(seed_data)
                try:
                    op(data, random.Random(seed))
                except MutationNotApplicable:
                    continue
                parse_scenario(data, source=f"<{name}@{path.name}>")


# -- classifier: dead vs divergent --------------------------------------------


def _broken_trigger_mutant():
    """Mutant whose agent regex no longer matches: content stays
    attack-shaped, but the run produces no agent-fired tool call."""
    data = copy.deepcopy(SEED_DATA)
    rule = data["agents"]["reader"]["rules"][0]
    rule["match"] = rule["match"].replace("PAY:", "SETTLE:")
    return data


def test_dead_mutant_is_not_divergent():
    # Regression for the review finding: a mutation that breaks the
    # scripted regex yields a clean verdict on an empty execution — that
    # is a dead mutant, not an oracle divergence.
    data = _broken_trigger_mutant()
    scn = parse_scenario(data, source="<dead>")
    seed = load_scenario(ATTACK)
    verdict, trace = judge_with_trace(scn, "none")
    assert not verdict.violation
    assert fuzzer._attack_shaped(data)       # payload still looks injected
    assert not fuzzer._meaningful_execution(trace)
    assert classify(seed, data, verdict, "none", trace) == "dead"


def test_meaningful_execution_excludes_initial_task_reads():
    # The broken mutant still performs the runner's initial docs.read
    # (source "user"); that alone must not count as meaningful execution.
    data = _broken_trigger_mutant()
    scn = parse_scenario(data, source="<dead>")
    _, trace = judge_with_trace(scn, "none")
    tool_calls = [e for e in trace.events if e.kind == "tool_call"]
    assert tool_calls and all(e.source == "user" for e in tool_calls)


def test_grant_expansion_guard_still_neutral():
    # A mutant whose grant covers the seed's unauthorized actions is
    # legitimately clean: not divergent, not dead (execution happened).
    data = copy.deepcopy(SEED_DATA)
    data["grant"]["allowed_actions"] = [
        "docs.read", "payment.prepare", "payment.execute"]
    scn = parse_scenario(data, source="<expanded>")
    seed = load_scenario(ATTACK)
    verdict, trace = judge_with_trace(scn, "none")
    assert not verdict.violation
    assert fuzzer._meaningful_execution(trace)
    assert fuzzer._attack_shaped(data)
    assert classify(seed, data, verdict, "none", trace) == "neutral"


def test_envelope_clean_dead_mutant_counts_dead_not_neutral():
    data = _broken_trigger_mutant()
    scn = parse_scenario(data, source="<dead-env>")
    seed = load_scenario(ATTACK)
    verdict, trace = judge_with_trace(scn, "envelope")
    assert not verdict.violation
    assert classify(seed, data, verdict, "envelope", trace) == "dead"


def test_campaign_counts_dead_and_static_invalid(tmp_path):
    # attack-009 with this seed exercises dead mutants (broken execution
    # paths) and statically-broken mutants (e.g. source_swap moves a
    # resource a content-driven read still points at): the latter are
    # rejected as invalid PRE-RUN by _dangling_resource_refs instead of
    # crashing the engine mid-run.
    report = run_campaign(DIVERGENT_ATTACK, budget=60, seed=1,
                          defense="none", out=tmp_path / "out",
                          minimize=False)
    assert report["counts"]["dead"] >= 1
    assert report["invalid"] >= 1
    assert report["errors"] == 0   # static rejection caught them pre-run
    counts = report["counts"]
    assert counts["bypass"] + counts["divergent"] + counts["neutral"] \
        + counts["dead"] == report["valid"]
    assert report["valid"] + report["invalid"] + report["duplicates"] \
        + report["errors"] == report["mutants_run"]


def test_engine_exception_never_aborts_campaign(tmp_path, monkeypatch):
    # The runtime safety net: ANY engine exception during a mutant run
    # is caught and counted as errors — the campaign completes.
    real = fuzzer.judge_with_trace
    calls = {"n": 0}

    def flaky(scn, defense_name):
        calls["n"] += 1
        if calls["n"] % 3 == 0:
            raise RuntimeError("simulated engine crash")
        return real(scn, defense_name)

    monkeypatch.setattr(fuzzer, "judge_with_trace", flaky)
    report = run_campaign(ATTACK, budget=20, seed=3, defense="envelope",
                          out=tmp_path / "out", minimize=False)
    assert report["mutants_run"] == 20
    assert report["errors"] >= 1
    assert report["valid"] + report["invalid"] + report["duplicates"] \
        + report["errors"] == report["mutants_run"]


# -- static resource-reference validation ------------------------------------


def test_dangling_refs_clean_on_all_shipped_scenarios():
    # The static check must never reject a shipped scenario (no false
    # positives: write-created ids, per-agent content flow, child
    # results are all modelled).
    for path in sorted((ROOT / "scenarios").rglob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert fuzzer._dangling_resource_refs(data) == [], path.name


def test_dangling_refs_detects_source_swap_breakage():
    # Moving msg-101 from emails to docs leaves the NEW_MAIL-driven
    # email.read pointing at a missing id: statically rejected.
    data = copy.deepcopy(ATTACK_011)
    fuzzer.source_swap(data, random.Random(1))
    refs = fuzzer._dangling_resource_refs(data)
    assert refs and "msg-101" in refs[0]


def test_dangling_refs_detects_uppercased_capture():
    # payload_wording's uppercase variant rewrites the NEW_MAIL line;
    # the capture then renders MSG-101, which does not exist.
    data = copy.deepcopy(ATTACK_011)
    fuzzer._set_line(data, "docs", "inbox-brief", 1,
                     fuzzer._get_line(data, "docs", "inbox-brief", 1).upper())
    refs = fuzzer._dangling_resource_refs(data)
    assert refs and "MSG-101" in refs[0]


def test_dangling_refs_ignores_dead_and_write_created():
    # A rule that never fires produces no reference; an id a docs.write
    # creates counts as existing.
    data = copy.deepcopy(SEED_DATA)
    assert fuzzer._dangling_resource_refs(data) == []
    data["agents"]["reader"]["rules"][0]["match"] = "NEVER_MATCHES"
    assert fuzzer._dangling_resource_refs(data) == []


# -- all-seeds smoke -----------------------------------------------------------


def test_all_attack_seeds_campaign_smoke(tmp_path):
    for path in sorted(ATTACK_DIR.glob("*.yaml")):
        out = tmp_path / path.stem
        report = run_campaign(path, budget=15, seed=5, defense="envelope",
                              out=out, minimize=False)
        counts = report["counts"]
        assert counts["bypass"] + counts["divergent"] + counts["neutral"] \
            + counts["dead"] == report["valid"], path.name
        assert report["valid"] + report["invalid"] + report["duplicates"] \
            + report["errors"] == report["mutants_run"], path.name
        assert (out / "campaign.json").is_file()
