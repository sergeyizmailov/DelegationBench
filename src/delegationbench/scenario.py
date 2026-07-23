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
- rule templates (``${name}`` placeholders) may only reference MANDATORY
  capture groups of the rule's ``match`` regex — groups that participate
  in every possible match. A template referencing an optional group
  (``(...)?``, ``(...)*``, or one alternation branch) would crash
  mid-run with a KeyError when the group does not participate, so the
  loader rejects it with a clear ScenarioError (fail closed: rejecting
  is safer than rendering an empty string in a security testbed).
- ``task.read`` (non-empty) requires the root agent to hold the
  ``docs.read`` capability AND the grant to allow ``docs.read`` — the
  runner's initial reads would otherwise fail mid-run (capability) or
  exceed the grant. Capability overreach in agent RULES stays a runtime
  ``CapabilityError`` by design; only the root task's reads are
  validated at load time.
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

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .actions import DOCS_READ, PAYMENT_EXECUTE, resolve_actions
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


_QUANTIFIER = re.compile(r"\{(\d+)(?:,\d*)?\}")


class _UnanalyzablePattern(Exception):
    """Internal: the pattern uses a construct the group analyzer does not
    model; treated as "no group is provably mandatory"."""


class _GroupAnalyzer:
    """Compute the capture-group numbers guaranteed to participate in
    EVERY match of a pattern — i.e. never ``None`` in ``groupdict()``.

    Sequences union their atoms' mandatory groups; a quantifier that
    allows zero repetitions (``*``, ``?``, ``{0,…}``) and alternation
    branches the group is absent from make a group optional; captures
    inside negative lookarounds never participate. Group numbering
    follows ``re`` (opening parens, left to right). Anything the
    analyzer does not model raises :class:`_UnanalyzablePattern`, which
    the caller maps to "nothing is provably mandatory" — fail closed.
    """

    def __init__(self, src: str) -> None:
        self.src = src
        self.n = len(src)
        self.groups = 0   # capturing-group counter (re numbering order)

    def analyze(self) -> frozenset[int]:
        _, mandatory = self._alternation(0)
        return frozenset(mandatory)

    def _alternation(self, i: int) -> tuple[int, set[int]]:
        mandatory: set[int] | None = None
        while True:
            seq: set[int] = set()
            while i < self.n and self.src[i] not in ")|":
                i, atom, zero_ok = self._quantified(i)
                if not zero_ok:
                    seq |= atom
            mandatory = seq if mandatory is None else mandatory & seq
            if i < self.n and self.src[i] == "|":
                i += 1
            else:
                return i, mandatory if mandatory is not None else set()

    def _quantified(self, i: int) -> tuple[int, set[int], bool]:
        """One atom plus an optional quantifier; returns (next index,
        the atom's mandatory groups, whether the quantifier allows zero
        repetitions)."""
        i, atom = self._atom(i)
        if i >= self.n:
            return i, atom, False
        c = self.src[i]
        if c in "*?":
            zero_ok = True
            i += 1
        elif c == "+":
            zero_ok = False
            i += 1
        elif c == "{":
            m = _QUANTIFIER.match(self.src, i)
            if m is None:
                return i, atom, False   # literal '{', not a quantifier
            zero_ok = int(m.group(1)) == 0
            i = m.end()
        else:
            return i, atom, False
        if i < self.n and self.src[i] in "?+":   # lazy/possessive marker
            i += 1
        return i, atom, zero_ok

    def _atom(self, i: int) -> tuple[int, set[int]]:
        c = self.src[i]
        if c == "\\":
            return min(i + 2, self.n), set()
        if c == "[":
            return self._skip_class(i), set()
        if c == "(":
            return self._group(i)
        return i + 1, set()

    def _skip_class(self, i: int) -> int:
        i += 1
        if i < self.n and self.src[i] == "^":
            i += 1
        if i < self.n and self.src[i] == "]":
            i += 1
        while i < self.n and self.src[i] != "]":
            i += 2 if self.src[i] == "\\" else 1
        if i >= self.n:
            raise _UnanalyzablePattern
        return i + 1

    def _close(self, i: int) -> int:
        if i >= self.n or self.src[i] != ")":
            raise _UnanalyzablePattern
        return i + 1

    def _capturing(self, i: int) -> tuple[int, set[int]]:
        """Parse a capturing group's body opened at index ``i`` (just
        past the paren/prefix) and tag its own group number mandatory."""
        self.groups += 1
        num = self.groups
        j, m = self._alternation(i)
        return self._close(j), m | {num}

    def _group(self, i: int) -> tuple[int, set[int]]:
        src = self.src
        if not src.startswith("(?", i):
            return self._capturing(i + 1)
        if src.startswith("(?P<", i):
            end = src.find(">", i + 4)
            if end == -1:
                raise _UnanalyzablePattern
            return self._capturing(end + 1)
        if src.startswith("(?P=", i) or src.startswith("(?#", i):
            # Backreference / comment: no nested parens, no captures.
            end = src.find(")", i + 3)
            if end == -1:
                raise _UnanalyzablePattern
            return end + 1, set()
        if src.startswith("(?(", i):   # conditional (?(id)yes|no)
            end = src.find(")", i + 3)
            if end == -1:
                raise _UnanalyzablePattern
            j, m = self._alternation(end + 1)
            return self._close(j), m
        for prefix, negative in (("(?<=", False), ("(?<!", True),
                                 ("(?=", False), ("(?!", True)):
            if src.startswith(prefix, i):
                j, m = self._alternation(i + len(prefix))
                # Captures in NEGATIVE lookarounds never participate.
                return self._close(j), set() if negative else m
        if src.startswith("(?:", i) or src.startswith("(?>", i):
            j, m = self._alternation(i + 3)
            return self._close(j), m
        # Inline flags: (?aiLmsux-) or scoped (?aiLmsux:...)
        j = i + 2
        while j < self.n and src[j] in "aiLmsux-":
            j += 1
        if j < self.n and src[j] == ")":
            return j + 1, set()
        if j < self.n and src[j] == ":":
            k, m = self._alternation(j + 1)
            return self._close(k), m
        raise _UnanalyzablePattern


def _mandatory_groups(pattern: str) -> frozenset[int]:
    """Capture-group numbers that participate in EVERY match of
    ``pattern``. On any construct the analyzer does not model, returns
    ``frozenset()`` — nothing is provably mandatory, so templates
    referencing groups are refused at load time (fail closed)."""
    try:
        return _GroupAnalyzer(pattern).analyze()
    except (_UnanalyzablePattern, IndexError, ValueError):
        return frozenset()


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
    if not isinstance(g, dict):
        raise _err(path, "grant", "must be a mapping")
    allowed = _check_actions(path, _require(path, g, "allowed_actions",
                                            "grant.allowed_actions"),
                             "grant.allowed_actions", known)
    if not allowed:
        raise _err(path, "grant.allowed_actions", "must not be empty")
    max_depth = _require(path, g, "max_delegation_depth",
                         "grant.max_delegation_depth")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) \
            or max_depth < 0:
        raise _err(path, "grant.max_delegation_depth",
                   "must be a non-negative integer")
    ttl = g.get("ttl_seconds")
    if ttl is not None and (isinstance(ttl, bool)
                            or not isinstance(ttl, (int, float))
                            or not math.isfinite(ttl) or ttl <= 0):
        raise _err(path, "grant.ttl_seconds",
                   "must be a positive finite number or null")
    grant = Grant(frozenset(allowed), max_depth, ttl)

    # resources
    res_raw = d.get("resources") or {}
    if not isinstance(res_raw, dict):
        raise _err(path, "resources", "must be a mapping")
    stores: dict[str, dict[str, str]] = {}
    for store in ("docs", "emails", "config"):
        content = res_raw.get(store) or {}
        if not isinstance(content, dict):
            raise _err(path, f"resources.{store}", "must be a mapping")
        stores[store] = {str(k): str(v) for k, v in content.items()}
    resources = Resources(**stores)

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
    if not isinstance(t, dict):
        raise _err(path, "task", "must be a mapping")
    root_agent = str(_require(path, t, "agent", "task.agent"))
    if root_agent not in agents:
        raise _err(path, "task.agent", f"unknown agent {root_agent!r}")
    read_raw = t.get("read") or []
    if not isinstance(read_raw, list):
        raise _err(path, "task.read", "must be a list of doc ids")
    read = [str(x) for x in read_raw]
    for doc_id in read:
        if doc_id not in resources.docs:
            raise _err(path, "task.read",
                       f"doc {doc_id!r} not defined in resources.docs")
    if read:
        # The runner's initial reads execute under the root envelope;
        # validate them at load time instead of failing mid-run.
        if DOCS_READ not in agents[root_agent].capabilities:
            raise _err(path, "task.read",
                       f"root agent {root_agent!r} lacks the "
                       f"{DOCS_READ!r} capability required to read the "
                       "task's resources")
        if DOCS_READ not in grant.allowed_actions:
            raise _err(path, "task.read",
                       f"{DOCS_READ!r} is not in grant.allowed_actions: "
                       "the root task's reads would exceed the grant")
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
        if not isinstance(e, dict):
            raise _err(path, "expect", "must be a mapping")
        verdict = _require(path, e, "verdict", "expect.verdict")
        if verdict not in ("violation", "clean"):
            raise _err(path, "expect.verdict",
                       f"must be 'violation' or 'clean', got {verdict!r}")
        kinds_raw = e.get("violation_kinds") or []
        if not isinstance(kinds_raw, list):
            raise _err(path, "expect.violation_kinds", "must be a list")
        kinds = [str(k) for k in kinds_raw]
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


def _template_args(path: Path, body: dict, ctx: str) -> list[str]:
    """Stringified arg values of a delegate/tool body; ``args`` must be
    a mapping."""
    args = body.get("args") or {}
    if not isinstance(args, dict):
        raise _err(path, f"{ctx}.args", "must be a mapping")
    return [str(v) for v in args.values()]


def _parse_agent(path: Path, name: str, spec: dict,
                 known: frozenset[str]) -> Agent:
    if not isinstance(spec, dict):
        raise _err(path, f"agents.{name}", "must be a mapping")
    caps = frozenset(_check_actions(path, spec.get("capabilities") or [],
                                    f"agents.{name}.capabilities", known))
    rules_raw = spec.get("rules") or []
    if not isinstance(rules_raw, list):
        raise _err(path, f"agents.{name}.rules",
                   "must be a list of mappings")
    rules = []
    for i, r in enumerate(rules_raw):
        ctx = f"agents.{name}.rules[{i}]"
        if not isinstance(r, dict):
            raise _err(path, ctx, "must be a mapping")
        match = _require(path, r, "match", ctx)
        if not isinstance(match, str):
            raise _err(path, f"{ctx}.match", "must be a string (regex)")
        try:
            pattern = re.compile(match)
        except re.error as e:
            raise _err(path, f"{ctx}.match", f"invalid regex: {e}") from e
        then = _require(path, r, "then", ctx)
        if not isinstance(then, dict):
            raise _err(path, f"{ctx}.then",
                       "must be a mapping containing exactly one of: "
                       "delegate, tool, return")
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
            templates += _template_args(path, body, f"{ctx}.then.delegate")
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
            templates = _template_args(path, body, f"{ctx}.then.tool")
            if body.get("as_principal") is not None:
                templates.append(str(body["as_principal"]))
        else:  # return
            if not isinstance(body, str):
                raise _err(path, f"{ctx}.then.return", "must be a string")
            templates = [body]
        mandatory = _mandatory_groups(match)
        for tmpl in templates:
            for var in _TEMPLATE_VAR.findall(tmpl):
                if var not in pattern.groupindex:
                    raise _err(path, ctx,
                               f"template variable ${{{var}}} has no "
                               f"matching capture group in 'match'")
                if pattern.groupindex[var] not in mandatory:
                    raise _err(path, ctx,
                               f"template variable ${{{var}}} references "
                               f"optional capture group {var!r}: the "
                               "group does not participate in every "
                               "match, so the template would fail "
                               "mid-run; make the group mandatory or "
                               "drop the reference")
        advance = r.get("advance_clock", 0)
        if isinstance(advance, bool) \
                or not isinstance(advance, (int, float)) \
                or not math.isfinite(advance) or advance < 0:
            raise _err(path, f"{ctx}.advance_clock",
                       "must be a non-negative finite number")
        replay = r.get("replay", False)
        if not isinstance(replay, bool):
            raise _err(path, f"{ctx}.replay", "must be a boolean")
        rules.append(Rule(pattern=pattern, then={kind: body},
                          advance_clock=float(advance), replay=replay))
    return Agent(name=name, capabilities=caps, rules=rules)
