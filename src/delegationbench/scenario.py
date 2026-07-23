"""YAML scenario loader and validation (schema v1).

Loads a scenario file into dataclasses, raising ScenarioError with
file/field context on any validation problem. Regexes are compiled and
template placeholders are checked against capture-group names here, so a
bad scenario fails at load time, not mid-run.

Schema v1 field notes:

- ``agents.<name>.rules[].advance_clock`` (number, default 0): advance the
  virtual clock before the rule fires (models expiry attacks, V4).
- ``agents.<name>.rules[].replay`` (bool, default false): emit the same
  delegation twice with the same envelope nonce (models replay, V4).
- ``agents.<name>.rules[].then.tool.untracked`` (bool, default false):
  execute the tool call with a detached envelope and trace no delegation
  edge, so the call has no path back to the root grant (models an
  orchestrator bypass / origin loss, V5).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .actions import ACTIONS
from .agents import Agent, Rule

SCHEMA_VERSION = 1
SCENARIO_TYPES = ("attack", "benign")
VIOLATION_KINDS = ("V1", "V2", "V3", "V4", "V5", "V6")
_TEMPLATE_VAR = re.compile(r"\$\{(\w+)\}")


class ScenarioError(ValueError):
    pass


@dataclass
class Grant:
    allowed_actions: frozenset[str]
    max_delegation_depth: int
    ttl_seconds: float | None = None   # envelope expiry relative to run start


@dataclass
class Resources:
    docs: dict[str, str] = field(default_factory=dict)
    emails: dict[str, str] = field(default_factory=dict)
    config: dict[str, str] = field(default_factory=dict)


@dataclass
class TaskSpec:
    agent: str
    read: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Expect:
    verdict: str                                # "violation" | "clean"
    violation_kinds: list[str] = field(default_factory=list)
    unauthorized_actions: list[str] = field(default_factory=list)


@dataclass
class Scenario:
    id: str
    name: str
    type: str
    description: str
    principal: str
    grant: Grant
    resources: Resources
    agents: dict[str, Agent]
    task: TaskSpec
    expect: Expect | None = None
    path: str = ""


def load_scenario(path: str | Path) -> Scenario:
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ScenarioError(f"{path}: cannot read file: {e}") from e
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ScenarioError(f"{path}: invalid YAML: {e}") from e
    if not isinstance(data, dict):
        raise ScenarioError(f"{path}: top level must be a mapping")
    return _parse(path, data)


def parse_scenario(data: dict, source: str = "<data>") -> Scenario:
    """Validate an already-parsed scenario mapping (e.g. a fuzzer mutant)
    without touching the filesystem. ``source`` is used in error messages."""
    if not isinstance(data, dict):
        raise ScenarioError(f"{source}: top level must be a mapping")
    return _parse(Path(source), data)


def _err(path: Path, field_path: str, msg: str) -> ScenarioError:
    return ScenarioError(f"{path}: {field_path}: {msg}")


def _require(path: Path, data: dict, key: str, ctx: str):
    if key not in data:
        raise _err(path, ctx, f"missing required key {key!r}")
    return data[key]


def _check_actions(path: Path, values, ctx: str) -> list[str]:
    if not isinstance(values, list) or not all(
            isinstance(v, str) for v in values):
        raise _err(path, ctx, "must be a list of action ids")
    for v in values:
        if v not in ACTIONS:
            raise _err(path, ctx, f"unknown action {v!r} "
                                  f"(known: {sorted(ACTIONS)})")
    return values


def _parse(path: Path, d: dict) -> Scenario:
    schema = _require(path, d, "schema", "schema")
    if schema != SCHEMA_VERSION:
        raise _err(path, "schema",
                   f"unsupported schema {schema!r} (expected {SCHEMA_VERSION})")
    scn_id = _require(path, d, "id", "id")
    name = _require(path, d, "name", "name")
    scn_type = _require(path, d, "type", "type")
    if scn_type not in SCENARIO_TYPES:
        raise _err(path, "type",
                   f"must be one of {SCENARIO_TYPES}, got {scn_type!r}")
    principal = _require(path, d, "principal", "principal")

    # grant
    g = _require(path, d, "grant", "grant")
    allowed = _check_actions(path, _require(path, g, "allowed_actions",
                                            "grant.allowed_actions"),
                             "grant.allowed_actions")
    if not allowed:
        raise _err(path, "grant.allowed_actions", "must not be empty")
    max_depth = _require(path, g, "max_delegation_depth",
                         "grant.max_delegation_depth")
    if not isinstance(max_depth, int) or max_depth < 0:
        raise _err(path, "grant.max_delegation_depth",
                   "must be a non-negative integer")
    ttl = g.get("ttl_seconds")
    if ttl is not None and (not isinstance(ttl, (int, float)) or ttl <= 0):
        raise _err(path, "grant.ttl_seconds",
                   "must be a positive number or null")
    grant = Grant(frozenset(allowed), max_depth, ttl)

    # resources
    res_raw = d.get("resources") or {}
    resources = Resources(
        docs={str(k): str(v) for k, v in (res_raw.get("docs") or {}).items()},
        emails={str(k): str(v)
                for k, v in (res_raw.get("emails") or {}).items()},
        config={str(k): str(v)
                for k, v in (res_raw.get("config") or {}).items()})

    # agents
    agents_raw = _require(path, d, "agents", "agents")
    if not isinstance(agents_raw, dict) or not agents_raw:
        raise _err(path, "agents", "must be a non-empty mapping")
    agents: dict[str, Agent] = {}
    for aname, aspec in agents_raw.items():
        agents[str(aname)] = _parse_agent(path, str(aname), aspec or {})

    # task
    t = _require(path, d, "task", "task")
    root_agent = str(_require(path, t, "agent", "task.agent"))
    if root_agent not in agents:
        raise _err(path, "task.agent", f"unknown agent {root_agent!r}")
    read = [str(x) for x in (t.get("read") or [])]
    for doc_id in read:
        if doc_id not in resources.docs:
            raise _err(path, "task.read",
                       f"doc {doc_id!r} not defined in resources.docs")
    task = TaskSpec(agent=root_agent, read=read,
                    description=str(t.get("description", "")))

    # delegation targets must exist (checked after all agents parsed)
    for aname, agent in agents.items():
        for i, rule in enumerate(agent.rules):
            target = rule.then.get("delegate", {}).get("agent")
            if target is not None and target not in agents:
                raise _err(path, f"agents.{aname}.rules[{i}].then.delegate",
                           f"unknown agent {target!r}")

    # expect
    expect = None
    if "expect" in d and d["expect"] is not None:
        e = d["expect"]
        verdict = _require(path, e, "verdict", "expect.verdict")
        if verdict not in ("violation", "clean"):
            raise _err(path, "expect.verdict",
                       f"must be 'violation' or 'clean', got {verdict!r}")
        kinds = [str(k) for k in (e.get("violation_kinds") or [])]
        for k in kinds:
            if k not in VIOLATION_KINDS:
                raise _err(path, "expect.violation_kinds",
                           f"unknown kind {k!r} (known: {VIOLATION_KINDS})")
        unauth = _check_actions(path, e.get("unauthorized_actions") or [],
                                "expect.unauthorized_actions")
        expect = Expect(verdict=verdict, violation_kinds=kinds,
                        unauthorized_actions=unauth)

    return Scenario(id=str(scn_id), name=str(name), type=scn_type,
                    description=str(d.get("description", "")),
                    principal=str(principal), grant=grant,
                    resources=resources, agents=agents, task=task,
                    expect=expect, path=str(path))


def _parse_agent(path: Path, name: str, spec: dict) -> Agent:
    caps = frozenset(_check_actions(path, spec.get("capabilities") or [],
                                    f"agents.{name}.capabilities"))
    rules = []
    for i, r in enumerate(spec.get("rules") or []):
        ctx = f"agents.{name}.rules[{i}]"
        match = _require(path, r, "match", ctx)
        try:
            pattern = re.compile(match)
        except re.error as e:
            raise _err(path, f"{ctx}.match", f"invalid regex: {e}") from e
        then = _require(path, r, "then", ctx)
        kinds = [k for k in ("delegate", "tool", "return") if k in then]
        if len(kinds) != 1:
            raise _err(path, f"{ctx}.then",
                       "must contain exactly one of: delegate, tool, return")
        kind = kinds[0]
        body = then[kind]
        if kind == "delegate":
            if not isinstance(body, dict):
                raise _err(path, f"{ctx}.then.delegate", "must be a mapping")
            _require(path, body, "agent", f"{ctx}.then.delegate")
            _check_actions(path, body.get("actions") or [],
                           f"{ctx}.then.delegate.actions")
            templates = [str(body.get("task", ""))]
            templates += [str(v)
                          for v in (body.get("args") or {}).values()]
        elif kind == "tool":
            if not isinstance(body, dict):
                raise _err(path, f"{ctx}.then.tool", "must be a mapping")
            action = _require(path, body, "action", f"{ctx}.then.tool")
            if action not in ACTIONS:
                raise _err(path, f"{ctx}.then.tool.action",
                           f"unknown action {action!r}")
            untracked = body.get("untracked", False)
            if not isinstance(untracked, bool):
                raise _err(path, f"{ctx}.then.tool.untracked",
                           "must be a boolean")
            templates = [str(v) for v in (body.get("args") or {}).values()]
        else:  # return
            if not isinstance(body, str):
                raise _err(path, f"{ctx}.then.return", "must be a string")
            templates = [body]
        for tmpl in templates:
            for var in _TEMPLATE_VAR.findall(tmpl):
                if var not in pattern.groupindex:
                    raise _err(path, ctx,
                               f"template variable ${{{var}}} has no "
                               f"matching capture group in 'match'")
        advance = r.get("advance_clock", 0)
        if not isinstance(advance, (int, float)) or advance < 0:
            raise _err(path, f"{ctx}.advance_clock",
                       "must be a non-negative number")
        replay = r.get("replay", False)
        if not isinstance(replay, bool):
            raise _err(path, f"{ctx}.replay", "must be a boolean")
        rules.append(Rule(pattern=pattern, then={kind: body},
                          advance_clock=float(advance), replay=replay))
    return Agent(name=name, capabilities=caps, rules=rules)
