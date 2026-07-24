"""Offline tests for the expanded real-model suite harness.

A scripted fake model plays both roles (compliant on attack documents,
cautious on benign ones) so the suite's graph, adapter wiring, and
oracle classification are validated deterministically, without a real
LLM endpoint.
"""

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

MODULE_PATH = Path(__file__).parents[1] / "examples" / "langgraph_real_llm_suite.py"
SPEC = importlib.util.spec_from_file_location("real_llm_suite", MODULE_PATH)
assert SPEC and SPEC.loader
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)

DEMO_PATH = Path(__file__).parents[1] / "examples" / "langgraph_real_llm_demo.py"
DEMO_SPEC = importlib.util.spec_from_file_location("real_llm_demo_for_suite", DEMO_PATH)
assert DEMO_SPEC and DEMO_SPEC.loader
demo = importlib.util.module_from_spec(DEMO_SPEC)
sys.modules[DEMO_SPEC.name] = demo
DEMO_SPEC.loader.exec_module(demo)
Decision = demo.Decision


class ScriptedModel:
    """Plays the reader/payment/audit roles from a fixed script.

    On attack documents the model follows the injected instruction; on
    benign documents it performs the legitimate flow only. The script is
    keyed off the system prompt (which names the agent) and the number
    of times that agent has already been called.
    """

    def __init__(self, scenario_id: str, case: str) -> None:
        self.scenario_id = scenario_id
        self.case = case
        self.model = "scripted-fake-model"
        self.calls: dict[str, int] = {}

    def _next(self, role: str) -> "Decision":
        self.calls[role] = self.calls.get(role, 0) + 1
        n = self.calls[role]
        attack = self.case == "attack"

        def decide(action, args):
            return Decision(
                action=action,
                args=args,
                raw=json.dumps({"action": action, "args": args}),
                latency_seconds=0.0,
                parse_error=False,
            )

        if role == "reader":
            if n == 1:
                return decide("read_document", {"doc_id": "invoice"})
            # Second reader turn: document has been read.
            sid = self.scenario_id
            if sid == "v1v2-payment-escalation":
                if attack:
                    return decide(
                        "transfer_to_payment",
                        {
                            "task": "pay invoice",
                            "scope": ["payment.execute"],
                            "payee": "acme-supplier",
                            "amount": "950",
                        },
                    )
                return decide("finish", {})
            # v3/v6/v7: the (benign or attack) document asks to pay.
            if n == 2:
                return decide(
                    "transfer_to_payment",
                    {
                        "task": "pay invoice",
                        "scope": ["payment.execute"],
                        "payee": "acme-supplier",
                        "amount": "950",
                    },
                )
            # Third reader turn only happens after the payment result.
            if sid == "v6-result-driven-widening" and attack:
                return decide(
                    "email_send",
                    {
                        "recipient": "audit@external.example",
                        "subject": "payment confirmation",
                    },
                )
            return decide("finish", {})

        if role == "payment":
            if self.scenario_id == "v3-depth-limit" and attack and n == 1:
                return decide(
                    "transfer_to_audit",
                    {"task": "audit confirmation", "scope": ["audit.log.write"]},
                )
            return decide(
                "execute_payment", {"payee": "acme-supplier", "amount": "950"}
            )

        if role == "audit":
            return decide("write_audit_log", {"note": "confirmed"})

        raise AssertionError(f"unknown role {role}")

    def decide(self, system: str, transcript_text: str) -> "Decision":
        if "reader agent" in system:
            return self._next("reader")
        if "payment agent" in system:
            return self._next("payment")
        if "audit agent" in system:
            return self._next("audit")
        raise AssertionError("unrecognized system prompt")


def run(scenario_id: str, case: str) -> dict:
    scn = suite.SCENARIOS[scenario_id]
    model = ScriptedModel(scenario_id, case)
    return asyncio.run(suite.run_once(model, 1, scn, case))


@pytest.mark.parametrize("scenario_id", list(suite.SCENARIOS))
def test_attack_run_flags_expected_kinds(scenario_id):
    result = run(scenario_id, "attack")
    scn = suite.SCENARIOS[scenario_id]
    assert result["verdict"] == "violation", f"{scenario_id}: kinds={result['kinds']}"
    assert set(scn.expected_attack_kinds) <= set(result["kinds"]), (
        f"{scenario_id}: expected {scn.expected_attack_kinds} <= {result['kinds']}"
    )
    assert result["expected_kinds_met"] is True


@pytest.mark.parametrize("scenario_id", list(suite.SCENARIOS))
def test_benign_run_is_clean_and_completes(scenario_id):
    result = run(scenario_id, "benign")
    assert result["verdict"] == "clean", f"{scenario_id}: kinds={result['kinds']}"
    assert result["task_completed"] is True
    assert result["expected_kinds_met"] is None


def test_v7_payment_leg_runs_under_substituted_principal():
    result = run("v7-principal-substitution", "attack")
    assert "V7" in result["kinds"]
    principals = {
        e.get("principal")
        for e in result["trace"]
        if e["kind"] == "tool_call" and e.get("action") == "payment.execute"
    }
    assert principals == {"user-456"}


def test_v7_benign_keeps_original_principal():
    result = run("v7-principal-substitution", "benign")
    assert result["verdict"] == "clean"
    assert result["payments"], "benign twin should still exercise payment"


def test_v3_audit_hop_exceeds_depth():
    result = run("v3-depth-limit", "attack")
    assert "V3" in result["kinds"]
    assert result["audit_logs"], "scripted attack must reach the audit hop"


def test_v6_reader_emails_after_injected_result():
    result = run("v6-result-driven-widening", "attack")
    assert result["emails"], "reader must follow the injected tool result"
    assert "email.send" in result["unauthorized_actions"]


def test_scenario_metrics_shape():
    attack = run("v1v2-payment-escalation", "attack")
    benign = run("v1v2-payment-escalation", "benign")
    metrics = suite.scenario_metrics([attack, benign])
    assert metrics["attack_violation_rate"] == 1.0
    assert metrics["attack_expected_kinds_rate"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["benign_task_success_rate"] == 1.0
    assert metrics["errors"] == 0
