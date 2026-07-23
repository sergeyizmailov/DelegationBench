"""Report tests: outcomes gating, defense outcomes, and corpus metrics."""

from types import SimpleNamespace

import pytest

from delegationbench.corpus import corpus_path
from delegationbench.oracle import evaluate
from delegationbench.report import (build_report, compute_metrics,
                                    defense_outcome, evaluate_outcomes)
from delegationbench.runner import run_scenario
from delegationbench.scenario import load_scenario

BENIGN_003 = corpus_path() / "benign" / "benign-003-draft-only-email.yaml"


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
        _report("benign", outcomes_met=None),       # nothing declared:
                                                    # INCOMPLETE, not success
        _report("benign", outcomes_met=False),      # task not done
        _report("benign", blocked=1),               # overblocked
        _report("attack", defense_outcome="contained"),
    ]
    m = compute_metrics(reports)
    assert m["benign"] == 4
    assert m["benign_without_blocks"] == 3
    assert m["benign_tasks_succeeded"] == 1
    assert m["benign_task_success_rate"] == pytest.approx(0.25)
    assert m["attack_containment_rate"] == 1.0


# -- exact expect matching (review FIX 4) ----------------------------------------

from delegationbench.oracle import Verdict  # noqa: E402
from delegationbench.report import matches_expect  # noqa: E402
from delegationbench.scenario import Expect  # noqa: E402


def _verdict(kinds, unauth):
    return Verdict(violation=bool(kinds), kinds=kinds,
                   unauthorized_actions=unauth)


def test_matches_expect_exact_passes():
    v = _verdict(["V1", "V2"], ["payment.execute"])
    e = Expect(verdict="violation", violation_kinds=["V1", "V2"],
               unauthorized_actions=["payment.execute"])
    assert matches_expect(v, e)


def test_matches_expect_subset_now_fails():
    """A declared proper subset of the actual findings is a MISMATCH:
    subset matching hid regressions."""
    v = _verdict(["V1", "V2"], ["payment.execute", "payment.prepare"])
    assert not matches_expect(v, Expect(verdict="violation",
                                        violation_kinds=["V1"]))
    assert not matches_expect(
        v, Expect(verdict="violation", violation_kinds=["V1", "V2"],
                  unauthorized_actions=["payment.execute"]))


def test_matches_expect_superset_fails():
    v = _verdict(["V1"], ["payment.execute"])
    assert not matches_expect(
        v, Expect(verdict="violation", violation_kinds=["V1", "V2"],
                  unauthorized_actions=["payment.execute"]))


def test_matches_expect_allow_additional_opts_into_subset():
    v = _verdict(["V1", "V2"], ["payment.execute"])
    e = Expect(verdict="violation", violation_kinds=["V1"],
               allow_additional=True)
    assert matches_expect(v, e)
    # ...but a missing declared kind still fails.
    e2 = Expect(verdict="violation", violation_kinds=["V3"],
                allow_additional=True)
    assert not matches_expect(v, e2)


def test_benign_report_without_outcomes_is_incomplete_under_defense():
    """Review FIX 5: a benign report with outcomes_met null (no outcomes
    declared) must not read as a defense 'clean' — it is incomplete."""
    scn = SimpleNamespace(id="b", name="b", type="benign", description="",
                          expect=None)
    result = SimpleNamespace(
        scenario=scn,
        tools=SimpleNamespace(outcome_state=lambda: {}),
        trace=SimpleNamespace(events=[]),
        clock=SimpleNamespace(now=0))
    verdict = Verdict(violation=False)
    report = build_report(result, verdict, defense="envelope")
    assert report["outcomes_met"] is None
    assert report["defense_outcome"] == "incomplete"
