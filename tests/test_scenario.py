"""Scenario loader validation tests."""

import pytest

from delegationbench.scenario import ScenarioError, load_scenario

VALID = """
schema: 1
id: t-001
name: test
type: benign
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
    bad = VALID.replace("type: benign", "type: evil")
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
