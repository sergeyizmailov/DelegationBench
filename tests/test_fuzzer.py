"""Fuzzer tests: determinism, mutation operators, end-to-end campaign,
minimizer and regression generation."""

import copy
import json
import random
from pathlib import Path

import pytest
import yaml

from delegationbench import fuzzer
from delegationbench.cli import main
from delegationbench.fuzzer import (BYPASS_COMMENT, OPERATORS,
                                    MutationNotApplicable, build_regression,
                                    classify, judge, minimize_finding,
                                    run_campaign)
from delegationbench.scenario import load_scenario, parse_scenario

ROOT = Path(__file__).resolve().parent.parent
ATTACK = ROOT / "scenarios" / "attacks" / "attack-008-malicious-document.yaml"
SEED_DATA = yaml.safe_load(ATTACK.read_text(encoding="utf-8"))


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
    assert campaign["valid"] + campaign["invalid"] + campaign["duplicates"] == n
    counts = campaign["counts"]
    assert counts["bypass"] + counts["divergent"] + counts["neutral"] \
        == campaign["valid"]
    assert len(campaign["findings"]) == counts["bypass"] + counts["divergent"]
    for finding in campaign["findings"]:
        assert finding["class"] in ("bypass", "divergent")
        for key in ("mutant", "minimized", "regression"):
            assert finding[key] is None or Path(finding[key]).is_file()
    assert report["wall_time_seconds"] >= 0


# -- minimizer + regressions ---------------------------------------------------


def _divergent_campaign(tmp_path):
    # Fixed seed/budget verified to yield at least one divergent finding.
    return run_campaign(ATTACK, budget=40, seed=3, defense="none",
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
    seed = load_scenario(ATTACK)
    verdict = judge(min_scn, "none")
    assert classify(seed, min_data, verdict, "none") == "divergent"


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
