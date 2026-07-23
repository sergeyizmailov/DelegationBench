"""Scenario runner: executes a scenario and produces a Trace.

The runner builds the root envelope from the user grant, reads the root
task's resources, and lets the scripted agents drive everything else.
A defense object may hook delegation and tool-call boundaries; the
default (``--defense none``) is no hook at all.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Protocol

from .agents import DEFAULT_MAX_CHAIN, Agent, run_task
from .clock import VirtualClock
from .envelope import Envelope
from .scenario import Scenario
from .tools import Tools
from .trace import BlockedError, Trace


class Defense(Protocol):
    """Hook point for reference defenses under test.

    Implementations raise ``trace.BlockedError`` to block the action: the
    engine records a ``blocked`` event (with the reason) in the trace and
    skips it — the tool never executes, the delegation edge never happens.

    Optional integration points (duck-typed): if the defense exposes
    ``bind(clock, grant_actions, principal)`` the runner calls it once
    before the run starts; if it exposes ``signing_key`` (bytes), the
    runner signs the root envelope with that key so derived envelopes
    are signed too.
    """

    def before_delegation(self, agent: Agent, parent: Envelope,
                          child: Envelope, task: str,
                          scope: frozenset[str]) -> None: ...

    def before_tool_call(self, agent: Agent, env: Envelope, action: str,
                         args: dict, source: str) -> None: ...


@dataclass
class RunContext:
    clock: VirtualClock
    trace: Trace
    tools: Tools
    agents: dict[str, Agent]
    defense: Defense | None
    _nonce_counter: "itertools.count"
    # Delegation-chain budget: guards against cyclic/runaway delegation
    # hitting RecursionError before the trace event cap (agents.py).
    max_chain: int = DEFAULT_MAX_CHAIN
    chain_depth: int = 0

    def next_nonce(self) -> str:
        return f"nonce-{next(self._nonce_counter)}"


@dataclass
class RunResult:
    scenario: Scenario
    trace: Trace
    clock: VirtualClock
    tools: Tools


def run_scenario(scn: Scenario, defense: Defense | None = None,
                 max_events: int = 10_000,
                 max_chain: int = DEFAULT_MAX_CHAIN) -> RunResult:
    clock = VirtualClock()
    trace = Trace(clock, max_events=max_events)
    tools = Tools(trace, docs=scn.resources.docs,
                  emails=scn.resources.emails, config=scn.resources.config)
    ctx = RunContext(clock=clock, trace=trace, tools=tools,
                     agents=scn.agents, defense=defense,
                     _nonce_counter=itertools.count(1),
                     max_chain=max_chain)

    if defense is not None:
        bind = getattr(defense, "bind", None)
        if bind is not None:
            bind(clock, scn.grant.allowed_actions, scn.principal)

    root_env = Envelope(
        principal=scn.principal,
        task_id="root",
        allowed_actions=scn.grant.allowed_actions,
        max_delegation_depth=scn.grant.max_delegation_depth,
        depth=0,
        expires_at=scn.grant.ttl_seconds,
        nonce="nonce-root")
    # The principal -> root boundary is trusted: the runner issues (and, if
    # the defense signs, signs) the root envelope. Derived envelopes
    # re-sign themselves in derive().
    signing_key = getattr(defense, "signing_key", None)
    if signing_key is not None:
        root_env = root_env.sign(signing_key)

    root_agent = scn.agents[scn.task.agent]
    trace.delegation(None, root_env.task_id, root_agent.name,
                     sorted(root_env.allowed_actions), depth=0,
                     nonce=root_env.nonce, expires_at=root_env.expires_at,
                     source="user", principal=root_env.principal,
                     task=scn.task.description, args={})

    # Root agent reads the task's resources first; the concatenated
    # content (provenance: document) is what its rules scan. These reads
    # go through the same defense hook as every other tool call: the
    # principal -> root boundary establishes the grant, it does not
    # exempt the root agent from it.
    parts = []
    for doc_id in scn.task.read:
        if defense is not None:
            try:
                defense.before_tool_call(root_agent, root_env, "docs.read",
                                         {"doc_id": doc_id}, "user")
            except BlockedError as e:
                trace.blocked(root_env.task_id, root_agent.name,
                              phase="tool_call", reason=str(e),
                              source="user", action="docs.read",
                              args={"doc_id": doc_id},
                              principal=root_env.principal)
                continue
        parts.append(tools.call(root_agent, root_env, "docs.read",
                                {"doc_id": doc_id}, "user"))
    if parts:
        run_task(root_agent, root_env, "\n".join(parts), "document", ctx)

    return RunResult(scenario=scn, trace=trace, clock=clock, tools=tools)
