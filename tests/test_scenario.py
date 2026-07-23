"""Scenario loader validation tests."""

import pytest

from delegationbench.scenario import ScenarioError, load_scenario

VALID = """
schema: 1
id: t-001
name: test
type: attack
description: minimal valid scenario
principal: user-123
grant:
  allowed_actions: [docs.read]
  max_delegation_depth: 1
  ttl_seconds: null
resources:
  docs:
    d1: "hello"
agents:
  reader:
    capabilities: [docs.read]
    rules: []
task:
  agent: reader
  read: [d1]
  description: "read a doc"
"""


def write(tmp_path, text):
    p = tmp_path / "scenario.yaml"
    p.write_text(text)
    return p


def test_valid_scenario_loads(tmp_path):
    scn = load_scenario(write(tmp_path, VALID))
    assert scn.id == "t-001"
    assert scn.grant.allowed_actions == frozenset({"docs.read"})
    assert scn.grant.ttl_seconds is None
    assert scn.expect is None
    assert "reader" in scn.agents


def test_missing_required_key(tmp_path):
    bad = VALID.replace("principal: user-123\n", "")
    with pytest.raises(ScenarioError, match="principal"):
        load_scenario(write(tmp_path, bad))


def test_bad_schema_version(tmp_path):
    bad = VALID.replace("schema: 1", "schema: 2")
    with pytest.raises(ScenarioError, match="schema"):
        load_scenario(write(tmp_path, bad))


def test_bad_type(tmp_path):
    bad = VALID.replace("type: attack", "type: evil")
    with pytest.raises(ScenarioError, match="type"):
        load_scenario(write(tmp_path, bad))


def test_unknown_action_in_grant(tmp_path):
    bad = VALID.replace("allowed_actions: [docs.read]",
                        "allowed_actions: [docs.read, shell.exec]")
    with pytest.raises(ScenarioError, match="shell.exec"):
        load_scenario(write(tmp_path, bad))


def test_invalid_regex(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: '(?P<oops>unclosed'\n"
        "        then: {return: 'x'}")
    with pytest.raises(ScenarioError, match="invalid regex"):
        load_scenario(write(tmp_path, bad))


def test_template_variable_without_capture_group(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'hello'\n"
        "        then: {return: '${missing}'}")
    with pytest.raises(ScenarioError, match="capture group"):
        load_scenario(write(tmp_path, bad))


def test_unknown_delegate_target(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'hello'\n"
        "        then:\n"
        "          delegate: {agent: ghost, task: 'x', actions: [docs.read], args: {}}")
    with pytest.raises(ScenarioError, match="ghost"):
        load_scenario(write(tmp_path, bad))


def test_unknown_root_agent(tmp_path):
    bad = VALID.replace("task:\n  agent: reader", "task:\n  agent: ghost")
    with pytest.raises(ScenarioError, match="task.agent"):
        load_scenario(write(tmp_path, bad))


def test_read_resource_must_exist(tmp_path):
    bad = VALID.replace("read: [d1]", "read: [nope]")
    with pytest.raises(ScenarioError, match="task.read"):
        load_scenario(write(tmp_path, bad))


def test_bad_expect_kind(tmp_path):
    bad = VALID + "\nexpect:\n  verdict: violation\n  violation_kinds: [V9]\n"
    with pytest.raises(ScenarioError, match="V9"):
        load_scenario(write(tmp_path, bad))


def test_untracked_must_be_bool(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'hello'\n"
        "        then: {tool: {action: docs.read, untracked: maybe}}")
    with pytest.raises(ScenarioError, match="untracked"):
        load_scenario(write(tmp_path, bad))


def test_invalid_yaml(tmp_path):
    with pytest.raises(ScenarioError, match="invalid YAML"):
        load_scenario(write(tmp_path, "schema: [1,\n"))


def test_error_message_has_file_context(tmp_path):
    bad = VALID.replace("schema: 1", "schema: 2")
    p = write(tmp_path, bad)
    with pytest.raises(ScenarioError) as excinfo:
        load_scenario(p)
    assert str(p) in str(excinfo.value)


# -- custom actions (DEFECT 5) ----------------------------------------------


def test_custom_actions_extend_builtins(tmp_path):
    text = VALID.replace("schema: 1",
                         "schema: 1\nactions: [crm.contacts.export]")
    text = text.replace("allowed_actions: [docs.read]",
                        "allowed_actions: [docs.read, crm.contacts.export]")
    text = text.replace("capabilities: [docs.read]",
                        "capabilities: [docs.read, crm.contacts.export]")
    scn = load_scenario(write(tmp_path, text))
    assert scn.actions == frozenset({"crm.contacts.export"})
    assert "crm.contacts.export" in scn.grant.allowed_actions


def test_undeclared_custom_action_rejected(tmp_path):
    bad = VALID.replace("allowed_actions: [docs.read]",
                        "allowed_actions: [docs.read, crm.contacts.export]")
    with pytest.raises(ScenarioError) as excinfo:
        load_scenario(write(tmp_path, bad))
    msg = str(excinfo.value)
    assert "unknown action(s) ['crm.contacts.export']" in msg
    assert "known:" in msg  # the message lists the known vocabulary


def test_unknown_action_in_rule_tool(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'go'\n"
        "        then: {tool: {action: database.query.execute}}")
    with pytest.raises(ScenarioError, match="database.query.execute"):
        load_scenario(write(tmp_path, bad))


def test_custom_action_in_rule_tool_accepted_when_declared(tmp_path):
    text = VALID.replace("schema: 1",
                         "schema: 1\nactions: [database.query.execute]")
    text = text.replace(
        "rules: []",
        "rules:\n      - match: 'go'\n"
        "        then: {tool: {action: database.query.execute}}")
    text = text.replace("capabilities: [docs.read]",
                        "capabilities: [docs.read, database.query.execute]")
    scn = load_scenario(write(tmp_path, text))
    assert scn.agents["reader"].rules[0].then["tool"]["action"] == \
        "database.query.execute"


def test_actions_must_be_list_of_ids(tmp_path):
    bad = VALID.replace("schema: 1", "schema: 1\nactions: 42")
    with pytest.raises(ScenarioError, match="actions"):
        load_scenario(write(tmp_path, bad))


# -- payment_limit validation (DEFECT 4) ------------------------------------


def test_payment_execute_requires_payment_limit(tmp_path):
    bad = VALID.replace("allowed_actions: [docs.read]",
                        "allowed_actions: [docs.read, payment.execute]")
    with pytest.raises(ScenarioError, match="payment_limit"):
        load_scenario(write(tmp_path, bad))


def test_payment_limit_must_be_integer(tmp_path):
    text = VALID.replace("allowed_actions: [docs.read]",
                         "allowed_actions: [docs.read, payment.execute]")
    text = text.replace('    d1: "hello"',
                        '    d1: "hello"\n  config: {payment_limit: "lots"}')
    with pytest.raises(ScenarioError, match="integer"):
        load_scenario(write(tmp_path, text))


def test_payment_limit_not_required_without_payment_execute(tmp_path):
    text = VALID.replace('    d1: "hello"',
                         '    d1: "hello"\n  config: {payment_limit: "lots"}')
    scn = load_scenario(write(tmp_path, text))
    assert scn.resources.config["payment_limit"] == "lots"


# -- expect.outcomes validation ------------------------------------------------


def test_outcomes_valid_loads(tmp_path):
    text = VALID + ("\nexpect:\n  verdict: clean\n  outcomes:\n"
                    "    docs_read: 1\n    emails_sent: 0\n"
                    "    config_unchanged: true\n")
    scn = load_scenario(write(tmp_path, text))
    assert scn.expect.outcomes == {"docs_read": 1, "emails_sent": 0,
                                   "config_unchanged": True}


def test_outcomes_unknown_key_rejected(tmp_path):
    bad = VALID + ("\nexpect:\n  verdict: clean\n  outcomes:\n"
                   "    shells_executed: 0\n")
    with pytest.raises(ScenarioError, match="unknown outcome"):
        load_scenario(write(tmp_path, bad))


def test_outcomes_counter_must_be_non_negative_int(tmp_path):
    for value in ("-1", "true", "lots"):
        bad = VALID + (f"\nexpect:\n  verdict: clean\n  outcomes:\n"
                       f"    docs_read: {value}\n")
        with pytest.raises(ScenarioError, match="non-negative integer"):
            load_scenario(write(tmp_path, bad))


def test_outcomes_config_unchanged_must_be_bool(tmp_path):
    bad = VALID + ("\nexpect:\n  verdict: clean\n  outcomes:\n"
                   "    config_unchanged: 1\n")
    with pytest.raises(ScenarioError, match="boolean"):
        load_scenario(write(tmp_path, bad))


def test_outcomes_must_be_mapping(tmp_path):
    bad = VALID + "\nexpect:\n  verdict: clean\n  outcomes: [docs_read]\n"
    with pytest.raises(ScenarioError, match="outcomes"):
        load_scenario(write(tmp_path, bad))


# -- as_principal validation (V7) ----------------------------------------------


def test_as_principal_loads(tmp_path):
    text = VALID.replace(
        "    rules: []",
        "    rules:\n      - match: 'AS:(?P<p>\\S+)'\n"
        "        then:\n"
        "          delegate: {agent: helper, task: 'x', actions: [docs.read],\n"
        "                     as_principal: '${p}', args: {}}\n"
        "  helper:\n    capabilities: [docs.read]\n    rules: []")
    scn = load_scenario(write(tmp_path, text))
    assert scn.agents["reader"].rules[0].then["delegate"]["as_principal"] \
        == "${p}"


def test_as_principal_must_be_string(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'go'\n"
        "        then: {tool: {action: docs.read, as_principal: 42}}")
    with pytest.raises(ScenarioError, match="as_principal"):
        load_scenario(write(tmp_path, bad))


def test_as_principal_template_var_needs_capture_group(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'go'\n"
        "        then: {tool: {action: docs.read, as_principal: '${p}'}}")
    with pytest.raises(ScenarioError, match="capture group"):
        load_scenario(write(tmp_path, bad))


def test_as_principal_and_untracked_are_mutually_exclusive(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'go'\n"
        "        then: {tool: {action: docs.read, untracked: true,\n"
        "               as_principal: 'user-a'}}")
    with pytest.raises(ScenarioError, match="mutually exclusive"):
        load_scenario(write(tmp_path, bad))


# -- benign scenarios must declare expect.outcomes (review FIX 5) ---------------


def test_benign_without_expect_rejected(tmp_path):
    bad = VALID.replace("type: attack", "type: benign")
    with pytest.raises(ScenarioError, match="expect"):
        load_scenario(write(tmp_path, bad))


def test_benign_without_outcomes_rejected(tmp_path):
    bad = VALID.replace("type: attack", "type: benign") + \
        "\nexpect:\n  verdict: clean\n"
    with pytest.raises(ScenarioError, match="expect.outcomes"):
        load_scenario(write(tmp_path, bad))


def test_benign_with_outcomes_loads(tmp_path):
    text = VALID.replace("type: attack", "type: benign") + \
        "\nexpect:\n  verdict: clean\n  outcomes:\n    docs_read: 1\n"
    scn = load_scenario(write(tmp_path, text))
    assert scn.expect.outcomes == {"docs_read": 1}


# -- expect.allow_additional (review FIX 4) -------------------------------------


def test_allow_additional_defaults_to_false(tmp_path):
    text = VALID + "\nexpect:\n  verdict: violation\n"
    scn = load_scenario(write(tmp_path, text))
    assert scn.expect.allow_additional is False


def test_allow_additional_loads(tmp_path):
    text = VALID + ("\nexpect:\n  verdict: violation\n"
                    "  violation_kinds: [V2]\n  allow_additional: true\n")
    scn = load_scenario(write(tmp_path, text))
    assert scn.expect.allow_additional is True


def test_allow_additional_must_be_bool(tmp_path):
    bad = VALID + "\nexpect:\n  verdict: violation\n  allow_additional: yes\n"
    # YAML parses bare 'yes' as True (bool), so use a string instead.
    bad = bad.replace("yes", "'maybe'")
    with pytest.raises(ScenarioError, match="allow_additional"):
        load_scenario(write(tmp_path, bad))


# -- static self-delegation rejection (review FIX 6) ----------------------------


def test_self_delegation_rejected(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'go'\n"
        "        then:\n"
        "          delegate: {agent: reader, task: 'x', "
        "actions: [docs.read], args: {}}")
    with pytest.raises(ScenarioError, match="self-delegation"):
        load_scenario(write(tmp_path, bad))


# -- optional capture groups in templates (review FIX 2) ------------------------


def test_template_referencing_optional_group_rejected(tmp_path):
    """A template referencing a group that does not participate in
    every match would crash mid-run with a KeyError; the loader must
    reject it instead."""
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'PAY(?::(?P<payee>\\S+))?'\n"
        "        then: {return: 'paid ${payee}'}")
    with pytest.raises(ScenarioError, match="optional capture group"):
        load_scenario(write(tmp_path, bad))


def test_template_referencing_alternation_only_group_rejected(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: '(?:(?P<opt>x)|y)'\n"
        "        then: {return: '${opt}'}")
    with pytest.raises(ScenarioError, match="optional capture group"):
        load_scenario(write(tmp_path, bad))


def test_template_referencing_star_group_rejected(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: '(?P<opt>x)*done'\n"
        "        then: {return: '${opt}'}")
    with pytest.raises(ScenarioError, match="optional capture group"):
        load_scenario(write(tmp_path, bad))


def test_template_mandatory_groups_still_load(tmp_path):
    """Groups that always participate — plain, quantified with min >= 1,
    or inside a mandatory lookahead — stay valid template sources."""
    text = VALID.replace(
        "rules: []",
        "rules:\n"
        "      - match: 'PAY:(?P<payee>\\S+):(?P<amount>\\d+)'\n"
        "        then: {return: '${payee} ${amount}'}\n"
        "      - match: 'REP:(?P<rep>ab)+'\n"
        "        then: {return: '${rep}'}\n"
        "      - match: '(?=(?P<look>LUCK))LUCK'\n"
        "        then: {return: '${look}'}")
    scn = load_scenario(write(tmp_path, text))
    assert len(scn.agents["reader"].rules) == 3


# -- non-mapping YAML nodes (review FIX 2) --------------------------------------


def test_agent_spec_must_be_mapping(tmp_path):
    bad = VALID.replace(
        "  reader:\n    capabilities: [docs.read]\n    rules: []",
        "  reader: 'just a string'")
    with pytest.raises(ScenarioError, match="agents.reader"):
        load_scenario(write(tmp_path, bad))


def test_resources_store_must_be_mapping(tmp_path):
    bad = VALID.replace('    d1: "hello"', "    [a, b]")
    with pytest.raises(ScenarioError, match="resources.docs"):
        load_scenario(write(tmp_path, bad))


def test_resources_must_be_mapping(tmp_path):
    bad = VALID.replace("resources:\n  docs:\n    d1: \"hello\"",
                        "resources: [docs]")
    with pytest.raises(ScenarioError, match="resources"):
        load_scenario(write(tmp_path, bad))


def test_then_must_be_mapping(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'hello'\n        then: 'return'")
    with pytest.raises(ScenarioError, match="then"):
        load_scenario(write(tmp_path, bad))


def test_rule_must_be_mapping(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - 'just a string'")
    with pytest.raises(ScenarioError, match=r"rules\[0\]"):
        load_scenario(write(tmp_path, bad))


def test_rules_must_be_list(tmp_path):
    bad = VALID.replace("    rules: []", "    rules: 'nope'")
    with pytest.raises(ScenarioError, match="rules"):
        load_scenario(write(tmp_path, bad))


def test_match_must_be_string(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 42\n        then: {return: 'x'}")
    with pytest.raises(ScenarioError, match="match"):
        load_scenario(write(tmp_path, bad))


def test_grant_must_be_mapping(tmp_path):
    bad = VALID.replace(
        "grant:\n  allowed_actions: [docs.read]\n"
        "  max_delegation_depth: 1\n  ttl_seconds: null",
        "grant: 42")
    with pytest.raises(ScenarioError, match="grant"):
        load_scenario(write(tmp_path, bad))


def test_task_must_be_mapping(tmp_path):
    bad = VALID.replace(
        "task:\n  agent: reader\n  read: [d1]\n"
        "  description: \"read a doc\"",
        "task: 'nope'")
    with pytest.raises(ScenarioError, match="task"):
        load_scenario(write(tmp_path, bad))


def test_task_read_must_be_list(tmp_path):
    bad = VALID.replace("  read: [d1]", "  read: d1")
    with pytest.raises(ScenarioError, match="task.read"):
        load_scenario(write(tmp_path, bad))


def test_expect_must_be_mapping(tmp_path):
    bad = VALID + "\nexpect: 'clean'\n"
    with pytest.raises(ScenarioError, match="expect"):
        load_scenario(write(tmp_path, bad))


def test_tool_args_must_be_mapping(tmp_path):
    bad = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'go'\n"
        "        then: {tool: {action: docs.read, args: [doc_id]}}")
    with pytest.raises(ScenarioError, match="args"):
        load_scenario(write(tmp_path, bad))


# -- numeric field robustness (review FIX 2) -------------------------------------


def test_ttl_seconds_rejects_bool_nan_inf(tmp_path):
    for value in ("yes", ".nan", ".inf", "-.inf"):
        bad = VALID.replace("ttl_seconds: null", f"ttl_seconds: {value}")
        with pytest.raises(ScenarioError, match="ttl_seconds"):
            load_scenario(write(tmp_path, bad))


def test_max_delegation_depth_rejects_bool(tmp_path):
    bad = VALID.replace("max_delegation_depth: 1",
                        "max_delegation_depth: yes")
    with pytest.raises(ScenarioError, match="max_delegation_depth"):
        load_scenario(write(tmp_path, bad))


def test_advance_clock_rejects_bool_nan_inf(tmp_path):
    for value in ("yes", ".nan", ".inf"):
        bad = VALID.replace(
            "rules: []",
            f"rules:\n      - match: 'go'\n"
            f"        advance_clock: {value}\n"
            "        then: {return: 'x'}")
        with pytest.raises(ScenarioError, match="advance_clock"):
            load_scenario(write(tmp_path, bad))


def test_advance_clock_accepts_valid_numbers(tmp_path):
    text = VALID.replace(
        "rules: []",
        "rules:\n      - match: 'go'\n"
        "        advance_clock: 1.5\n"
        "        then: {return: 'x'}")
    scn = load_scenario(write(tmp_path, text))
    assert scn.agents["reader"].rules[0].advance_clock == 1.5


# -- root task.read validated at load (review FIX 2) -----------------------------


def test_task_read_requires_root_capability(tmp_path):
    bad = VALID.replace("capabilities: [docs.read]", "capabilities: []")
    with pytest.raises(ScenarioError, match="task.read"):
        load_scenario(write(tmp_path, bad))


def test_task_read_requires_grant(tmp_path):
    bad = VALID.replace("allowed_actions: [docs.read]",
                        "allowed_actions: [email.read]")
    bad = bad.replace("capabilities: [docs.read]",
                      "capabilities: [docs.read, email.read]")
    with pytest.raises(ScenarioError, match="task.read"):
        load_scenario(write(tmp_path, bad))


def test_empty_task_read_needs_no_capability(tmp_path):
    text = VALID.replace("  read: [d1]", "  read: []")
    text = text.replace("capabilities: [docs.read]", "capabilities: []")
    scn = load_scenario(write(tmp_path, text))
    assert scn.task.read == []
