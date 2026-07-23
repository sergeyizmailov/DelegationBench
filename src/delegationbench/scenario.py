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
- ``agents.<name>.rules[].then.{delegate,tool}.as_principal`` (string,
  optional): stamp the derived delegation envelope (or the envelope the
  tool call executes under) with a different, content-derived principal
  instead of the parent envelope's. Models cross-user context confusion:
  the orchestrator is deceived into acting under another principal's
  identity; the orchestrator holds the signing key, so a substituted
  envelope still verifies (models V7, principal substitution).
- ``expect.outcomes`` (mapping, optional for attacks, REQUIRED for
  ``type: benign``): assertions on the final tool/store state, so a
  benign scenario only counts as a success when the task's side effects
  actually happened. Keys are the tool layer's generic per-store
  counters (``docs_read``, ``docs_written``, ``emails_read``,
  ``emails_sent``, ``drafts_created``, ``payments_prepared``,
  ``payments_executed`` — non-negative integers) plus
  ``config_unchanged`` (boolean: the config store equals its initial
  state). Only declared keys are checked.
- ``expect.allow_additional`` (bool, default false): opt back into
  subset matching for ``violation_kinds`` / ``unauthorized_actions``.
  By default the expect contract must match the oracle's findings
  EXACTLY — subset matching hides regressions.
- ``agents.<name>.rules[].then.delegate.agent`` may not name the agent
  itself: direct self-delegation loops are rejected at load time.
  Longer cycles are data-driven and are caught at run time by the
  engine's delegation-chain budget (``agents.EngineError``).
- ``actions`` (list of action ids, optional): scenario-declared custom
  actions extending the built-in registry. Every action referenced
  anywhere in the scenario (grant, capabilities, delegation scopes, tool
  rules, expect) must be a built-in or declared here. Custom actions
  execute via the tool layer's generic fallback.
- ``resources.config.payment_limit`` (integer-as-string): required
  whenever ``payment.execute`` is referenced anywhere in the scenario;
  the payment tool refuses executes above the limit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .actions import PAYMENT_EXECUTE, resolve_actions
from .agents import Agent, Rule
from .oracle import ALL_KINDS
from .tools import OUTCOME_COUNTERS, OUTCOME_KEYS, PAYMENT_LIMIT_KEY

SCHEMA_VERSION = 1
SCENARIO_TYPES = ("attack", "benign")
VIOLATION_KINDS = ALL_KINDS
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
    outcomes: dict = field(default_factory=dict)  # final tool-state assertions
    # Opt back into subset matching (declared kinds/actions may be a
    # proper subset of the oracle's findings). Default is exact matching.
    allow_additional: bool = False


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
    actions: frozenset[str] = frozenset()   # scenario-declared custom actions
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


def _check_actions(path: Path, values, ctx: str,
                   known: frozenset[str]) -> list[str]:
    if not isinstance(values, list) or not all(
            isinstance(v, str) for v in values):
        raise _err(path, ctx, "must be a list of action ids")
    unknown = sorted(set(values) - known)
    if unknown:
        raise _err(path, ctx, f"unknown action(s) {unknown} "
                              f"(known: {sorted(known)})")
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

    # scenario-declared custom actions extend the built-in registry
    declared_raw = d.get("actions") or []
    if not isinstance(declared_raw, list) or not all(
            isinstance(v, str) and v for v in declared_raw):
        raise _err(path, "actions",
                   "must be a list of non-empty action ids")
    declared = frozenset(declared_raw)
    known = resolve_actions(declared)

    # grant
    g = _require(path, d, "grant", "grant")
    allowed = _check_actions(path, _require(path, g, "allowed_actions",
                                            "grant.allowed_actions"),
                             "grant.allowed_actions", known)
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
        agents[str(aname)] = _parse_agent(path, str(aname), aspec or {},
                                          known)

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

    # delegation targets must exist (checked after all agents parsed);
    # a rule that delegates to the agent itself is a direct
    # self-delegation loop and is rejected statically (deeper cycles are
    # data-driven and are caught by the engine's delegation-chain budget
    # at run time — agents.EngineError).
    for aname, agent in agents.items():
        for i, rule in enumerate(agent.rules):
            target = rule.then.get("delegate", {}).get("agent")
            if target is not None and target not in agents:
                raise _err(path, f"agents.{aname}.rules[{i}].then.delegate",
                           f"unknown agent {target!r}")
            if target is not None and target == aname:
                raise _err(path, f"agents.{aname}.rules[{i}].then.delegate",
                           f"self-delegation loop: agent {aname!r} "
                           "delegates to itself")

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
                                "expect.unauthorized_actions", known)
        outcomes = _check_outcomes(path, e.get("outcomes"),
                                   "expect.outcomes")
        allow_additional = e.get("allow_additional", False)
        if not isinstance(allow_additional, bool):
            raise _err(path, "expect.allow_additional", "must be a boolean")
        expect = Expect(verdict=verdict, violation_kinds=kinds,
                        unauthorized_actions=unauth, outcomes=outcomes,
                        allow_additional=allow_additional)

    # A benign scenario only counts as a success when the task's side
    # effects actually happened, so expect.outcomes is REQUIRED for
    # type: benign — without it there is nothing to verify against.
    if scn_type == "benign":
        if expect is None:
            raise _err(path, "expect", "missing required key 'expect' "
                       "(type: benign must declare expect.outcomes)")
        if not expect.outcomes:
            raise _err(path, "expect.outcomes", "missing required field "
                       "'outcomes' (type: benign must assert the final "
                       "tool/store state)")

    # payment.execute needs a payment_limit to enforce: the config value
    # must exist and be an integer.
    referenced = set(grant.allowed_actions)
    for agent in agents.values():
        referenced |= set(agent.capabilities)
        for rule in agent.rules:
            if "delegate" in rule.then:
                referenced |= set(rule.then["delegate"].get("actions") or [])
            elif "tool" in rule.then:
                referenced.add(rule.then["tool"]["action"])
    if expect is not None:
        referenced |= set(expect.unauthorized_actions)
    if PAYMENT_EXECUTE in referenced:
        raw_limit = resources.config.get(PAYMENT_LIMIT_KEY)
        if raw_limit is None:
            raise _err(path, "resources.config",
                       f"{PAYMENT_LIMIT_KEY!r} is required when "
                       f"{PAYMENT_EXECUTE!r} is used")
        try:
            int(raw_limit)
        except ValueError:
            raise _err(path, "resources.config",
                       f"{PAYMENT_LIMIT_KEY!r} must be an integer, "
                       f"got {raw_limit!r}") from None

    return Scenario(id=str(scn_id), name=str(name), type=scn_type,
                    description=str(d.get("description", "")),
                    principal=str(principal), grant=grant,
                    resources=resources, agents=agents, task=task,
                    actions=declared,
                    expect=expect, path=str(path))


def _check_as_principal(path: Path, body: dict, ctx: str) -> None:
    value = body.get("as_principal")
    if value is not None and not isinstance(value, str):
        raise _err(path, f"{ctx}.as_principal", "must be a string")


def _check_outcomes(path: Path, raw, ctx: str) -> dict:
    """Validate the expect.outcomes contract: known keys only, counters
    are non-negative integers, config_unchanged is a boolean."""
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not raw:
        raise _err(path, ctx, "must be a non-empty mapping")
    for key, value in raw.items():
        if key not in OUTCOME_KEYS:
            raise _err(path, ctx, f"unknown outcome {key!r} "
                                  f"(known: {sorted(OUTCOME_KEYS)})")
        if key in OUTCOME_COUNTERS:
            if not isinstance(value, int) or isinstance(value, bool) \
                    or value < 0:
                raise _err(path, ctx, f"{key!r} must be a non-negative "
                                      f"integer, got {value!r}")
        elif not isinstance(value, bool):
            raise _err(path, ctx, f"{key!r} must be a boolean, "
                                  f"got {value!r}")
    return dict(raw)


def _parse_agent(path: Path, name: str, spec: dict,
                 known: frozenset[str]) -> Agent:
    caps = frozenset(_check_actions(path, spec.get("capabilities") or [],
                                    f"agents.{name}.capabilities", known))
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
                           f"{ctx}.then.delegate.actions", known)
            _check_as_principal(path, body, f"{ctx}.then.delegate")
            templates = [str(body.get("task", ""))]
            templates += [str(v)
                          for v in (body.get("args") or {}).values()]
            if body.get("as_principal") is not None:
                templates.append(str(body["as_principal"]))
        elif kind == "tool":
            if not isinstance(body, dict):
                raise _err(path, f"{ctx}.then.tool", "must be a mapping")
            action = _require(path, body, "action", f"{ctx}.then.tool")
            if action not in known:
                raise _err(path, f"{ctx}.then.tool.action",
                           f"unknown action(s) {[action]} "
                           f"(known: {sorted(known)})")
            untracked = body.get("untracked", False)
            if not isinstance(untracked, bool):
                raise _err(path, f"{ctx}.then.tool.untracked",
                           "must be a boolean")
            if untracked and body.get("as_principal") is not None:
                raise _err(path, f"{ctx}.then.tool",
                           "untracked and as_principal are mutually "
                           "exclusive (an untracked call has no envelope "
                           "to re-stamp)")
            _check_as_principal(path, body, f"{ctx}.then.tool")
            templates = [str(v) for v in (body.get("args") or {}).values()]
            if body.get("as_principal") is not None:
                templates.append(str(body["as_principal"]))
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
