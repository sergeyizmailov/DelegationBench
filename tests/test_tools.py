"""Tool-layer tests: payment_limit enforcement and the custom-action
fallback."""

import json

import pytest

from delegationbench.agents import Agent
from delegationbench.envelope import Envelope
from delegationbench.tools import (CapabilityError, Tools, ToolError,
                                   UnknownResourceError)
from delegationbench.trace import Trace

PAYER = Agent(name="payer",
              capabilities=frozenset({"payment.prepare", "payment.execute",
                                      "crm.contacts.export"}))


def make_tools(config=None):
    trace = Trace()
    return Tools(trace, config=config), trace


def make_env(**overrides):
    fields = dict(principal="user-123", task_id="root",
                  allowed_actions=PAYER.capabilities,
                  max_delegation_depth=1, nonce="n-root")
    fields.update(overrides)
    return Envelope(**fields)


def execute(tools, amount, env=None):
    return tools.call(PAYER, env or make_env(), "payment.execute",
                      {"payee": "vendor-77", "amount": str(amount)}, "user")


# -- payment_limit (DEFECT 4) ----------------------------------------------


def test_execute_above_limit_refused_and_not_recorded():
    tools, _ = make_tools(config={"payment_limit": "100"})
    result = json.loads(execute(tools, 950))
    assert result["status"] == "error"
    assert "exceeds payment_limit 100" in result["error"]
    # The payment is NOT recorded as executed.
    assert not any(p["status"] == "executed" for p in tools.payments)
    assert tools.payments == []


def test_execute_at_or_below_limit_recorded():
    tools, _ = make_tools(config={"payment_limit": "100"})
    assert json.loads(execute(tools, 100))["status"] == "executed"
    assert json.loads(execute(tools, 80))["status"] == "executed"
    assert [p["status"] for p in tools.payments] == ["executed", "executed"]


def test_raised_limit_then_execute_succeeds():
    """The attack-012 mechanism: admin.config.update raises the limit,
    and a later execute above the ORIGINAL limit goes through — sibling
    state contamination is now technically real."""
    tools, _ = make_tools(config={"payment_limit": "100"})
    assert json.loads(execute(tools, 950))["status"] == "error"
    tools.config["payment_limit"] = "100000"  # what admin.config.update does
    assert json.loads(execute(tools, 95000))["status"] == "executed"


def test_execute_requires_payment_limit_config():
    tools, _ = make_tools(config={})
    with pytest.raises(UnknownResourceError, match="payment_limit"):
        execute(tools, 10)


def test_non_integer_payment_limit_is_a_graceful_refusal():
    """payment_limit rewritten mid-run to a non-integer (e.g. via
    admin.config.update): the execute is refused with an error result —
    no uncaught ToolError, no payment recorded — consistent with the
    over-limit path."""
    tools, _ = make_tools(config={"payment_limit": "100"})
    tools.config["payment_limit"] = "lots"  # what a mid-run update can do
    result = json.loads(execute(tools, 10))
    assert result["status"] == "error"
    assert "integer" in result["error"]
    assert tools.payments == []


# -- payment amount validation (review FIX 3) ------------------------------------


def test_execute_non_positive_amount_refused():
    """A zero or negative payment is nonsense for the mock: refused
    with an error result, not recorded."""
    tools, _ = make_tools(config={"payment_limit": "1000"})
    for amount in ("0", "-50"):
        result = json.loads(execute(tools, amount))
        assert result["status"] == "error"
        assert "positive" in result["error"]
    assert tools.payments == []


def test_prepare_non_positive_amount_refused():
    tools, _ = make_tools(config={"payment_limit": "1000"})
    for amount in ("0", "-50"):
        result = json.loads(tools.call(
            PAYER, make_env(), "payment.prepare",
            {"payee": "v", "amount": amount}, "user"))
        assert result["status"] == "error"
        assert "positive" in result["error"]
    assert tools.payments == []


def test_execute_amount_must_be_integer():
    tools, _ = make_tools(config={"payment_limit": "100"})
    with pytest.raises(ToolError, match="integer"):
        execute(tools, "lots")


# -- generated email ids vs seeded ids (review FIX 3) -----------------------------

MAILER = Agent(name="mailer",
               capabilities=frozenset({"email.draft", "email.send"}))


def test_generated_email_ids_never_overwrite_seeded():
    """A scenario-seeded email id (e.g. draft-1) must not collide with
    the generated-id counter: generated ids skip occupied slots."""
    trace = Trace()
    tools = Tools(trace, emails={"draft-1": "seeded draft",
                                 "sent-1": "seeded sent"})
    r1 = tools.call(MAILER, make_env(), "email.draft",
                    {"to": "a@b", "subject": "s", "body": "b"}, "user")
    assert r1 == "drafted email draft-2"
    assert tools.emails["draft-1"] == "seeded draft"
    r2 = tools.call(MAILER, make_env(), "email.send",
                    {"to": "a@b", "subject": "s", "body": "b"}, "user")
    assert r2 == "sent email sent-3"  # counter shared with draft-2
    assert tools.emails["sent-1"] == "seeded sent"
    assert tools.emails["sent-3"].startswith("To: a@b")


def test_prepare_is_not_limited():
    tools, _ = make_tools(config={"payment_limit": "100"})
    result = json.loads(tools.call(PAYER, make_env(), "payment.prepare",
                                   {"payee": "v", "amount": "950"}, "user"))
    assert result["status"] == "prepared"


# -- custom-action fallback (DEFECT 5) --------------------------------------


def test_custom_action_uses_generic_fallback():
    tools, trace = make_tools()
    result = tools.call(PAYER, make_env(), "crm.contacts.export",
                        {"format": "csv"}, "user")
    assert json.loads(result) == {"status": "ok",
                                  "action": "crm.contacts.export"}
    kinds = [e.kind for e in trace.events]
    assert kinds == ["tool_call", "tool_result"]
    assert trace.events[0].detail["action"] == "crm.contacts.export"
    # The fallback records the principal of the authorizing envelope.
    assert trace.events[0].principal == "user-123"
    assert trace.events[1].principal == "user-123"


def test_custom_action_still_requires_capability():
    tools, _ = make_tools()
    agent = Agent(name="plain", capabilities=frozenset({"docs.read"}))
    with pytest.raises(CapabilityError, match="crm.contacts.export"):
        tools.call(agent, make_env(), "crm.contacts.export", {}, "user")


def test_builtin_actions_keep_their_handlers():
    tools, _ = make_tools()
    agent = Agent(name="writer", capabilities=frozenset({"docs.write"}))
    env = Envelope(principal="user-123", task_id="root",
                   allowed_actions=frozenset({"docs.write"}),
                   max_delegation_depth=1, nonce="n-root")
    result = tools.call(agent, env, "docs.write",
                        {"doc_id": "d1", "content": "hello"}, "user")
    assert result == "wrote doc d1"
    assert tools.docs["d1"] == "hello"
