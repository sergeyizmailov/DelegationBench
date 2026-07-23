"""Report tests: outcomes gating, defense outcomes, and corpus metrics."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from delegationbench.oracle import evaluate
from delegationbench.report import (build_report, compute_metrics,
                                    defense_outcome, evaluate_outcomes)
from delegationbench.runner import run_scenario
from delegationbench.scenario import load_scenario

ROOT = Path(__file__).resolve().parent.parent
BENIGN_003 = ROOT / "scenarios" / "benign" / "benign-003-draft-only-email.yaml"


def run(path):
    scn = load_scenario(path)
    result = run_scenario(scn)
    verdict = evaluate(result.trace, {
        "allowed_actions": scn.grant.allowed_actions,
        "max_delegation_depth": scn.grant.max_delegation_depth,
        "principal": scn.principal,
    })
    return scn, result, verdict


def test_evaluate_outcomes_detail():
    detail = evaluate_outcomes({"docs_read": 2, "emails_sent": 0},
                               {"docs_read": 2, "emails_sent": 1})
    assert detail["docs_read"] == {"expected": 2, "actual": 2, "met": True}
    assert detail["emails_sent"]["met"] is False
    assert evaluate_outcomes({}, {"docs_read": 0}) is None


def test_outcomes_met_passes_benign_expect():
    scn, result, verdict = run(BENIGN_003)
    report = build_report(result, verdict)
    assert report["outcomes_met"] is True
    assert report["expect_match"] is True
    assert report["outcomes"]["drafts_created"] == {
        "expected": 1, "actual": 1, "met": True}
    assert report["expect"]["outcomes"]["emails_sent"] == 0


def test_outcomes_unmet_fails_benign_expect(tmp_path):
    """A benign run that did nothing useful (here: declares an email sent
    that never happens) must NOT match its expect contract, even with a
    clean verdict and zero blocks."""
    p = tmp_path / "unmet.yaml"
    p.write_text(BENIGN_003.read_text().replace("emails_sent: 0",
                                                "emails_sent: 1"))
    scn, result, verdict = run(p)
    report = build_report(result, verdict)
    assert not verdict.violation
    assert report["blocked_calls"] == 0
    assert report["outcomes_met"] is False
    assert report["expect_match"] is False


def test_defense_outcome_incomplete_when_outcomes_unmet():
    clean = SimpleNamespace(blocked=[], violation=False)
    assert defense_outcome("benign", clean, outcomes_met=True) == "clean"
    assert defense_outcome("benign", clean, outcomes_met=False) == \
        "incomplete"
    overblocked = SimpleNamespace(blocked=[{"reason": "x"}],
                                  violation=False)
    assert defense_outcome("benign", overblocked,
                           outcomes_met=False) == "overblocked"
    # Attack containment is unaffected by outcomes.
    assert defense_outcome("attack", overblocked) == "contained"


def _report(scn_type, blocked=0, outcomes_met=True, defense_outcome=None):
    r = {"scenario": {"type": scn_type}, "unauthorized_calls": 0,
         "blocked_calls": blocked, "outcomes_met": outcomes_met}
    if defense_outcome is not None:
        r["defense_outcome"] = defense_outcome
    return r


def test_benign_task_success_rate_requires_zero_blocks_and_outcomes():
    reports = [
        _report("benign"),                          # success
        _report("benign", outcomes_met=None),       # nothing declared: met
        _report("benign", outcomes_met=False),      # task not done
        _report("benign", blocked=1),               # overblocked
        _report("attack", defense_outcome="contained"),
    ]
    m = compute_metrics(reports)
    assert m["benign"] == 4
    assert m["benign_without_blocks"] == 3
    assert m["benign_tasks_succeeded"] == 2
    assert m["benign_task_success_rate"] == pytest.approx(0.5)
    assert m["attack_containment_rate"] == 1.0
