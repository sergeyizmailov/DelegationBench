"""Tests for the adapter trace linter (validate-adapter)."""

import json

import pytest

from delegationbench.cli import main
from delegationbench.tracelint import TraceLintError, lint_trace, load_trace_document


def delegation(
    task_id,
    parent=None,
    agent="reader",
    scope=("docs.read",),
    depth=0,
    nonce="n-root",
    principal="user-a",
    expires=None,
):
    return {
        "kind": "delegation",
        "task_id": task_id,
        "parent_task": parent,
        "agent": agent,
        "scope": list(scope),
        "depth": depth,
        "nonce": nonce,
        "principal": principal,
        "expires_at": expires,
        "source": "user",
    }


def tool_call(task_id, agent="reader", action="docs.read", principal="user-a"):
    return {
        "kind": "tool_call",
        "task_id": task_id,
        "agent": agent,
        "action": action,
        "args": {},
        "principal": principal,
        "source": "user",
    }


def codes(findings):
    return [f.code for f in findings]


def test_clean_trace_has_no_findings():
    doc = {
        "events": [
            delegation("root"),
            delegation(
                "root/pay", parent="root", agent="payment", depth=1, nonce="n-1"
            ),
            tool_call("root/pay", agent="payment", action="payment.execute"),
        ]
    }
    assert lint_trace(doc, root_principal="user-a") == []


def test_multiple_roots_is_an_error():
    doc = {"events": [delegation("root"), delegation("root2", nonce="n-2")]}
    assert "E-MULTI-ROOT" in codes(lint_trace(doc))


def test_missing_root_is_an_error():
    doc = {"events": [tool_call("root")]}
    found = lint_trace(doc)
    assert "E-NO-ROOT" in codes(found)


def test_broken_parent_link():
    doc = {
        "events": [
            delegation("root"),
            delegation("child", parent="ghost", depth=1, nonce="n-1"),
        ]
    }
    assert "E-BROKEN-PARENT" in codes(lint_trace(doc))


def test_out_of_order_parent_is_a_warning():
    doc = {
        "events": [
            delegation("root"),
            delegation("child", parent="root/mid", depth=2, nonce="n-1"),
            delegation("root/mid", parent="root", depth=1, nonce="n-2"),
        ]
    }
    found = lint_trace(doc)
    assert "W-OUT-OF-ORDER" in codes(found)
    assert "E-BROKEN-PARENT" not in codes(found)


def test_task_rebinding():
    doc = {
        "events": [
            delegation("root"),
            delegation("t", parent="root", depth=1, nonce="n-1"),
            delegation("t", parent="other", depth=1, nonce="n-2"),
        ]
    }
    assert "E-REBIND" in codes(lint_trace(doc))


def test_same_binding_renewal_is_not_rebind():
    doc = {
        "events": [
            delegation("root"),
            delegation("t", parent="root", depth=1, nonce="n-1"),
            delegation("t", parent="root", depth=1, nonce="n-1b"),
        ]
    }
    assert "E-REBIND" not in codes(lint_trace(doc))


def test_agent_mismatch_on_tool_call():
    doc = {
        "events": [
            delegation("root"),
            tool_call("root", agent="payment"),
        ]
    }
    assert "E-AGENT-MISMATCH" in codes(lint_trace(doc))


def test_missing_principal_fails_when_grant_has_one():
    ev = delegation("root")
    ev["principal"] = ""
    doc = {"events": [ev, tool_call("root")]}
    assert "E-MISSING-PRINCIPAL" in codes(lint_trace(doc, root_principal="user-a"))


def test_unmapped_action_warns_against_vocabulary():
    doc = {
        "events": [
            delegation("root"),
            tool_call("root", action="read_doc"),  # raw framework name
        ]
    }
    found = lint_trace(doc, actions=frozenset({"docs.read"}))
    assert "W-UNMAPPED-ACTION" in codes(found)


def test_mapped_action_is_quiet():
    doc = {
        "events": [
            delegation("root"),
            tool_call("root", action="docs.read"),
        ]
    }
    found = lint_trace(doc, actions=frozenset({"docs.read"}))
    assert "W-UNMAPPED-ACTION" not in codes(found)


def test_duplicate_nonce_warns():
    doc = {
        "events": [
            delegation("root"),
            delegation("a", parent="root", depth=1, nonce="same"),
            delegation("b", parent="root", depth=1, nonce="same"),
        ]
    }
    assert "W-DUP-NONCE" in codes(lint_trace(doc))


def test_orphan_tool_call_warns():
    doc = {
        "events": [
            delegation("root"),
            tool_call("uncorrelated"),
        ]
    }
    assert "W-ORPHAN-TASK" in codes(lint_trace(doc))


def test_depth_inconsistency_warns():
    doc = {
        "events": [
            delegation("root"),
            delegation("child", parent="root", depth=5, nonce="n-1"),
        ]
    }
    assert "W-DEPTH-INCONSISTENT" in codes(lint_trace(doc))


def test_expiry_widening_warns():
    doc = {
        "events": [
            delegation("root", expires=100.0),
            delegation("child", parent="root", depth=1, nonce="n-1", expires=500.0),
        ]
    }
    assert "W-EXPIRY-WIDENING" in codes(lint_trace(doc))


def test_bare_event_list_accepted():
    doc = [delegation("root"), tool_call("root")]
    assert lint_trace(doc) == []


def test_bad_document_shape():
    with pytest.raises(TraceLintError):
        lint_trace({"no_events": True})


def test_empty_trace_is_an_error():
    assert "E-EMPTY" in codes(lint_trace({"events": []}))


def test_load_trace_document_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(TraceLintError):
        load_trace_document(path)


def _write(tmp_path, doc):
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(doc))
    return str(path)


def test_cli_clean_trace_exits_zero(tmp_path):
    trace = _write(tmp_path, {"events": [delegation("root"), tool_call("root")]})
    assert main(["validate-adapter", trace, "--strict"]) == 0


def test_cli_error_finding_exits_one_without_strict(tmp_path):
    trace = _write(
        tmp_path, {"events": [delegation("root"), delegation("root2", nonce="n-2")]}
    )
    assert main(["validate-adapter", trace]) == 1


def test_cli_warning_passes_without_strict_fails_with_strict(tmp_path):
    trace = _write(
        tmp_path, {"events": [delegation("root"), tool_call("uncorrelated")]}
    )
    assert main(["validate-adapter", trace]) == 0
    assert main(["validate-adapter", trace, "--strict"]) == 1


def test_cli_missing_file_exits_two(tmp_path):
    assert main(["validate-adapter", str(tmp_path / "nope.json")]) == 2


def test_cli_scenario_supplies_vocabulary(tmp_path, capsys):
    scenario = tmp_path / "scn.yaml"
    scenario.write_text(
        "schema: 1\n"
        "id: lint-vocab-001\n"
        "name: lint-vocab\n"
        "type: benign\n"
        "description: vocabulary fixture\n"
        "principal: user-a\n"
        "grant:\n"
        "  allowed_actions: [docs.read]\n"
        "  max_delegation_depth: 1\n"
        "agents:\n"
        "  reader:\n"
        "    capabilities: [docs.read]\n"
        "    rules: []\n"
        "task:\n"
        "  agent: reader\n"
        "expect:\n"
        "  verdict: clean\n"
        "  outcomes:\n"
        "    docs_read: 1\n"
    )
    trace = _write(
        tmp_path,
        {
            "events": [
                delegation("root"),
                tool_call("root", action="read_doc"),
            ]
        },
    )
    rc = main(["validate-adapter", trace, "--scenario", str(scenario), "--strict"])
    assert rc == 1
    assert "W-UNMAPPED-ACTION" in capsys.readouterr().out
