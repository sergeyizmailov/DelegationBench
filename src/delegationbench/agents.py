"""Scripted agent engine.

Agents stand in for LLM agents: naive instruction-followers. Each agent
has a capability manifest and an ordered list of rules. A rule's regex is
applied to content the agent has just read or received (tool results,
delegated task payload, child results); on a match it fires a tool call,
a delegation, or returns a result to the parent task.

Content is processed as a queue of (text, source) items so that results
produced mid-task are scanned by the same rules — this is what models
V6 (a malicious child result re-entering the parent).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .envelope import Envelope
from .trace import BlockedError, RunLimitExceeded

if TYPE_CHECKING:
    from .runner import RunContext

_TEMPLATE_VAR = re.compile(r"\$\{(\w+)\}")

# Delegation-chain budget: cyclic delegation (A delegates to B, B back to
# A) grows the run_task call stack one frame per hop and would hit
# RecursionError long before the trace's event cap. The engine aborts the
# chain well under the interpreter's recursion limit instead.
DEFAULT_MAX_CHAIN = 200


class EngineError(RunLimitExceeded):
    """The engine aborted the run: the delegation chain exceeded the
    chain budget (cyclic or runaway delegation). Subclasses
    ``RunLimitExceeded`` so existing runaway-run handling applies."""


def render_template(text: str, variables: dict[str, str]) -> str:
    """Substitute ${name} placeholders from regex capture groups."""
    def repl(m: re.Match) -> str:
        name = m.group(1)
        if name not in variables:
            raise KeyError(f"template variable ${{{name}}} has no value")
        return str(variables[name])
    return _TEMPLATE_VAR.sub(repl, text)


def render_args(args: dict, variables: dict[str, str]) -> dict:
    return {k: render_template(str(v), variables) for k, v in args.items()}


@dataclass
class Rule:
    pattern: re.Pattern
    then: dict                       # {"delegate": ...} | {"tool": ...} | {"return": ...}
    advance_clock: float = 0.0
    replay: bool = False


@dataclass
class Agent:
    name: str
    capabilities: frozenset[str]
    rules: list[Rule] = field(default_factory=list)


def run_task(agent: Agent, env: "Envelope", content: str, source: str,
             ctx: "RunContext") -> str:
    """Run one task; returns the result string passed back to the parent.

    Tracks the delegation-chain depth on the run context: a cyclic or
    runaway chain aborts with ``EngineError`` instead of growing the
    Python stack into a RecursionError."""
    if ctx.chain_depth >= ctx.max_chain:
        raise EngineError(
            f"delegation chain exceeded the engine's chain budget "
            f"({ctx.max_chain} nested tasks, at task {env.task_id}); "
            "aborting cyclic or runaway delegation")
    ctx.chain_depth += 1
    try:
        return _run_task(agent, env, content, source, ctx)
    finally:
        ctx.chain_depth -= 1


def _run_task(agent: Agent, env: "Envelope", content: str, source: str,
              ctx: "RunContext") -> str:
    queue: list[tuple[str, str]] = [(content, source)]
    while queue:
        text, src = queue.pop(0)
        for rule in agent.rules:
            m = rule.pattern.search(text)
            if not m:
                continue
            if rule.advance_clock:
                ctx.clock.advance(rule.advance_clock)
            variables = {k: v for k, v in m.groupdict().items()
                         if v is not None}
            if "tool" in rule.then:
                spec = rule.then["tool"]
                args = render_args(spec.get("args", {}), variables)
                call_env = env
                if spec.get("untracked"):
                    # Orchestrator bypass (V5): execute with a detached
                    # envelope and trace no delegation edge, so the call
                    # has no path back to the root grant.
                    call_env = Envelope(
                        principal="unknown",
                        task_id=f"untracked/{agent.name}",
                        allowed_actions=frozenset(),
                        max_delegation_depth=0)
                elif spec.get("as_principal") is not None:
                    # Principal substitution (V7): the agent was deceived
                    # into acting under another principal's identity.
                    call_env = env.with_principal(render_template(
                        spec["as_principal"], variables))
                if ctx.defense is not None:
                    try:
                        ctx.defense.before_tool_call(agent, call_env,
                                                     spec["action"], args,
                                                     src)
                    except BlockedError as e:
                        ctx.trace.blocked(call_env.task_id, agent.name,
                                          phase="tool_call", reason=str(e),
                                          source=src, action=spec["action"],
                                          args=args,
                                          principal=call_env.principal)
                        continue
                result = ctx.tools.call(agent, call_env, spec["action"], args,
                                        src)
                queue.append((result, "tool_result"))
            elif "delegate" in rule.then:
                spec = rule.then["delegate"]
                child = ctx.agents[spec["agent"]]
                task_text = render_template(spec.get("task", ""), variables)
                args = render_args(spec.get("args", {}), variables)
                scope = frozenset(spec.get("actions", []))
                child_env = env.derive(
                    task_id=f"{env.task_id}/{child.name}", scope=scope,
                    nonce=ctx.next_nonce())
                if spec.get("as_principal") is not None:
                    # Principal substitution (V7): content deceived the
                    # orchestrator into stamping the delegation with
                    # another principal's identity.
                    child_env = child_env.with_principal(render_template(
                        spec["as_principal"], variables))
                # replay: emit the same delegation (same envelope nonce)
                # twice; the defense checks each emission, so the second
                # one is rejected as a replay.
                for _ in range(2 if rule.replay else 1):
                    if ctx.defense is not None:
                        try:
                            ctx.defense.before_delegation(agent, env,
                                                          child_env,
                                                          task_text, scope)
                        except BlockedError as e:
                            ctx.trace.blocked(child_env.task_id, child.name,
                                              phase="delegation",
                                              reason=str(e), source=src,
                                              parent_task=env.task_id,
                                              scope=sorted(scope),
                                              task=task_text,
                                              principal=child_env.principal)
                            break
                    ctx.trace.delegation(
                        env.task_id, child_env.task_id, child.name,
                        sorted(scope), depth=child_env.depth,
                        nonce=child_env.nonce,
                        expires_at=child_env.expires_at, source=src,
                        principal=child_env.principal,
                        task=task_text, args=args)
                    child_input = "\n".join(
                        [task_text] + [f"{k}:{v}" for k, v in args.items()])
                    result = run_task(child, child_env, child_input, src,
                                      ctx)
                    if result:
                        queue.append((result, "child_result"))
            elif "return" in rule.then:
                return render_template(rule.then["return"], variables)
    return ""
