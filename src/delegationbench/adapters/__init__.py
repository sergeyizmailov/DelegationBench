"""Framework adapters: neutral event schema and trace reconstruction.

An adapter observes a framework's delegation/tool activity (callbacks,
tracers, middleware) and emits *neutral events* — plain dicts following
the schema below. :func:`build_trace` reconstructs a DelegationBench
:class:`~delegationbench.trace.Trace` from any such event stream, and
:func:`run_oracle` judges it against the user grant. Framework-specific
adapters (e.g. :mod:`delegationbench.adapters.langgraph`) only need to
produce these events; everything downstream is shared.

Neutral event schema
--------------------
Every event is a dict with a ``type`` key. ``run_id`` /
``parent_run_id`` form the run tree from which the delegation tree is
rebuilt: the nearest ancestor *agent* run of a tool run is the agent
that invoked it, and a delegation edge binds the first descendant agent
run of the destination agent — or, for same-graph handoffs
(``Command(goto=...)`` where the destination node run is a sibling of
the handoff tool run), the next unbound agent run of that agent.

``agent_start``
    ``run_id``, ``parent_run_id`` (None for the root run), ``agent``
    (node/agent name). Optional: ``principal`` (originating-user id —
    frameworks do not carry this by default; the harness must inject it,
    e.g. via config metadata), ``source``, ``task``, and ``task_id``.
    ``task_id`` is recommended when the same agent has multiple concurrent
    delegated tasks.
``agent_end``
    ``run_id``, ``agent``. Informational; ignored by ``build_trace``.
``delegation``
    One delegation edge, derived from a framework handoff mechanism
    (e.g. a ``transfer_to_*`` tool call). Keys: ``run_id`` (the handoff
    tool run), ``parent_run_id``, ``from_agent``, ``to_agent``,
    ``tool``, ``args``. Optional: ``scope`` (action ids the child is
    meant to receive; defaults to the parent's authority because
    framework handoffs carry no scope), ``source``, ``task``,
    ``principal``, and ``child_run_id``. The latter explicitly correlates
    a handoff to its destination run and is recommended for parallel or
    same-destination handoffs.
``tool_call``
    ``run_id``, ``parent_run_id``, ``agent``, ``tool``, ``args``.
    Optional: ``source``, ``principal``.
``tool_result``
    ``run_id`` (matching a prior ``tool_call`` run), ``ok`` (bool),
    and ``result`` or ``error`` (string). Results for handoff tool runs
    are ignored. A result whose ``run_id`` matches no prior tool call is
    NOT dropped: ``build_trace`` emits a synthetic ``tool_call`` for the
    :data:`UNCORRELATED` task so the oracle judges the anomaly (V5
    origin loss) instead of the run reading as clean. Optional:
    ``principal``.

``source`` follows :mod:`delegationbench.trace` provenance
(``user`` | ``document`` | ``tool_result`` | ``child_result``) and
defaults to ``user``.

Grant
-----
``build_trace``/``run_oracle`` take the same grant dict as
:func:`delegationbench.oracle.evaluate` — ``allowed_actions`` and
``max_delegation_depth`` — plus optional ``principal`` (recorded on the
root delegation for audit) and ``expires_at`` (virtual-clock seconds,
propagated down the chain so V4 can fire).

Principal
---------
Every trace event carries a first-class ``principal`` (the oracle
compares it against the root grant's principal for V7). ``build_trace``
stamps it from the events: the root task takes the root agent run's
``principal`` (falling back to ``grant["principal"]``), each delegation
inherits its parent task's principal unless the delegation event carries
its own, and tool events inherit their task's principal unless the event
carries one. Events without any principal in sight are stamped ``""``
(unknown). When the grant declares a principal, the oracle fails closed
and reports unknown identity as V5 origin loss.

Two event representations coexist in this package:

- **Neutral dict events** (schema above), consumed by
  :func:`build_trace` — run-tree-based reconstruction
  (``run_id``/``parent_run_id``), used by the LangGraph adapter.
- **AdapterEvent dataclasses** — task-graph-based
  (``task_id``/``parent_task`` already resolved by the adapter), used by
  the ROMA adapter, which ships its own ``build_trace``. New adapters
  should pick the representation that matches their framework's
  observation model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ..oracle import Verdict, evaluate
from ..trace import Trace

NeutralEvent = dict[str, Any]

EVENT_TYPES = ("agent_start", "agent_end", "delegation", "tool_call",
               "tool_result")

#: Task id for tool calls an adapter could not correlate to any task in
#: the delegation tree. The oracle judges these as V5 (origin loss).
UNCORRELATED = "uncorrelated"


@dataclass
class AdapterEvent:
    """Structured adapter event with the task graph already resolved.

    Alternative to the dict-based neutral events for frameworks where
    the adapter observes task ids directly (e.g. ROMA). ``kind`` is
    ``delegation`` | ``tool_call`` | ``tool_result``; ``task_id`` is the
    adapter-resolved task (:data:`UNCORRELATED` when unknown).
    ``depth``/``nonce``/``expires_at`` are envelope metadata passed
    through to the trace; ``time`` optionally overrides the virtual
    clock. ``principal`` is the originating-user id the event ran under
    ("" = unknown; child events inherit their task's principal in
    ``build_trace``). Adapters consuming this type provide their own
    ``build_trace`` (see ``delegationbench.adapters.roma``).
    """

    kind: str
    task_id: str
    parent_task: str | None = None
    agent: str = ""
    source: str = "user"
    scope: tuple = ()
    depth: int | None = None
    nonce: str = ""
    expires_at: float | None = None
    task: str = ""
    action: str = ""
    args: dict = field(default_factory=dict)
    result: str = ""
    time: float | None = None
    principal: str = ""


def build_trace(events: Iterable[NeutralEvent], grant: dict) -> Trace:
    """Rebuild a :class:`Trace` from neutral adapter events.

    The root delegation is synthesized from the grant: the first agent
    run with no agent ancestor becomes the root task holding the full
    ``allowed_actions`` scope. Each ``delegation`` event becomes a child
    delegation whose scope defaults to the parent's authority
    (attenuation-only). Tool calls outside any delegation path get an
    ``orphan-*`` task id so the oracle flags them as V5 (origin loss).
    """
    events = list(events)
    trace = Trace()

    agent_of_run: dict[str, str] = {}
    parent_of_run: dict[str, str | None] = {}
    for ev in events:
        rid = ev.get("run_id")
        if rid is not None:
            parent_of_run.setdefault(rid, ev.get("parent_run_id"))
        if ev.get("type") == "agent_start" and rid is not None:
            agent_of_run[rid] = ev.get("agent", "?")

    def nearest_agent_run(rid: str | None) -> str | None:
        seen: set[str] = set()
        while rid is not None and rid not in seen:
            seen.add(rid)
            if rid in agent_of_run:
                return rid
            rid = parent_of_run.get(rid)
        return None

    # Root: first agent run with no agent ancestor.
    root_run = next(
        (ev["run_id"] for ev in events
         if ev.get("type") == "agent_start" and ev.get("run_id") is not None
         and nearest_agent_run(parent_of_run.get(ev["run_id"])) is None),
        None,
    )

    # Bind each delegation (handoff tool run) to an agent run of the
    # destination agent. Two real framework shapes exist:
    # 1. Subgraph handoffs (Command.PARENT, subagents-as-tools): the
    #    destination agent run nests *under* the handoff tool run.
    # 2. Same-graph handoffs (a tool returning Command(goto="node")):
    #    the destination node run is a *sibling* of the tool run in the
    #    run tree; bind the next unbound agent_start of the destination
    #    agent in event order instead.
    bound_child: dict[str, str] = {}   # handoff tool run_id -> child agent run_id
    used_runs: set[str] = set()
    for idx, ev in enumerate(events):
        if ev.get("type") != "delegation":
            continue
        tool_run = ev.get("run_id")
        dest = ev.get("to_agent")
        explicit_child = ev.get("child_run_id")
        if (explicit_child is not None
                and explicit_child in agent_of_run
                and explicit_child not in used_runs):
            bound_child[tool_run] = explicit_child
            used_runs.add(explicit_child)
            continue
        for cand in events:
            rid = cand.get("run_id")
            if (cand.get("type") != "agent_start" or rid is None
                    or rid in used_runs or rid == root_run
                    or agent_of_run.get(rid) != dest):
                continue
            seen: set[str] = set()
            cur: str | None = rid
            while cur is not None and cur not in seen:
                seen.add(cur)
                if cur == tool_run:
                    bound_child[tool_run] = rid
                    used_runs.add(rid)
                    break
                cur = parent_of_run.get(cur)
            if tool_run in bound_child:
                break
        if tool_run not in bound_child:
            for cand in events[idx + 1:]:
                rid = cand.get("run_id")
                if (cand.get("type") == "agent_start" and rid is not None
                        and rid not in used_runs and rid != root_run
                        and agent_of_run.get(rid) == dest):
                    bound_child[tool_run] = rid
                    used_runs.add(rid)
                    break

    grant_actions = sorted(grant["allowed_actions"])
    task_of_run: dict[str, str] = {}
    scope_of_task: dict[str, list[str]] = {}
    depth_of_task: dict[str, int] = {}
    expires_of_task: dict[str, float | None] = {}
    principal_of_task: dict[str, str] = {}
    tasks_of_agent: dict[str, set[str]] = {}
    child_counts: dict[str, int] = {}
    tool_runs: dict[str, dict] = {}
    delegation_runs: set = set()   # handoff tool runs; their results are ignored

    for seq, ev in enumerate(events):
        etype = ev.get("type")
        rid = ev.get("run_id")
        if etype == "agent_start":
            if rid == root_run:
                principal = (ev.get("principal")
                             or grant.get("principal") or "")
                args: dict = {}
                if ev.get("principal") is not None:
                    args["principal"] = ev["principal"]
                trace.delegation(
                    None, rid, ev.get("agent", "?"), grant_actions, depth=0,
                    nonce="adapter-root", expires_at=grant.get("expires_at"),
                    source=ev.get("source", "user"), principal=principal,
                    task=ev.get("task", ""),
                    args=args)
                task_of_run[rid] = rid
                scope_of_task[rid] = grant_actions
                depth_of_task[rid] = 0
                expires_of_task[rid] = grant.get("expires_at")
                principal_of_task[rid] = principal
                tasks_of_agent.setdefault(
                    ev.get("agent", "?"), set()).add(rid)
            elif rid not in task_of_run:
                # Nested agent run not bound to a delegation: real graphs
                # wrap each agent in several chain runs (the node run and
                # the subgraph's inner graph run both carry the same
                # langgraph_node). Alias such runs to the nearest
                # enclosing agent run's task so their tool calls are not
                # orphaned. Runs bound to a delegation keep their own
                # task (they were registered when the delegation event
                # was processed, before this agent_start).
                ancestor = nearest_agent_run(parent_of_run.get(rid))
                if ancestor is not None and ancestor in task_of_run:
                    task_of_run[rid] = task_of_run[ancestor]
                else:
                    explicit_task = ev.get("task_id")
                    candidates = tasks_of_agent.get(
                        ev.get("agent", "?"), set())
                    if (explicit_task is not None
                            and explicit_task in scope_of_task):
                        task_of_run[rid] = explicit_task
                    elif len(candidates) == 1:
                        # Repeated executions of one StateGraph agent node
                        # are sibling chain runs, not new delegations. Reuse
                        # its only known task. Parallel same-agent tasks must
                        # supply task_id/child_run_id to avoid guessing.
                        task_of_run[rid] = next(iter(candidates))
        elif etype == "delegation":
            delegation_runs.add(rid)
            parent_run = nearest_agent_run(ev.get("parent_run_id"))
            parent_task = (task_of_run.get(parent_run) if parent_run
                           else None)
            if parent_task is None and root_run is not None:
                parent_task = task_of_run.get(root_run)
            dest = ev.get("to_agent") or "?"
            child_run = bound_child.get(rid)
            if child_run is not None:
                task_id = child_run
            else:
                base = f"{parent_task or 'root'}/{dest}"
                n = child_counts.get(base, 0)
                child_counts[base] = n + 1
                task_id = base if n == 0 else f"{base}#{n + 1}"
            scope = (sorted(ev["scope"]) if ev.get("scope") is not None
                     else scope_of_task.get(parent_task, grant_actions))
            depth = depth_of_task.get(parent_task, -1) + 1
            expires = expires_of_task.get(parent_task)
            principal = (ev["principal"] if "principal" in ev
                         else principal_of_task.get(parent_task, ""))
            trace.delegation(
                parent_task, task_id, dest, scope, depth=depth,
                nonce=f"adapter-{seq}", expires_at=expires,
                source=ev.get("source", "user"), principal=principal,
                task=ev.get("task", ""),
                args=ev.get("args") or {})
            if child_run is not None:
                task_of_run[child_run] = task_id
            scope_of_task[task_id] = scope
            depth_of_task[task_id] = depth
            expires_of_task[task_id] = expires
            principal_of_task[task_id] = principal
            tasks_of_agent.setdefault(dest, set()).add(task_id)
        elif etype == "tool_call":
            agent_run = nearest_agent_run(ev.get("parent_run_id"))
            task_id = task_of_run.get(agent_run)
            if task_id is None:
                # No delegation path to the root: oracle flags V5.
                task_id = f"orphan-{rid}"
            agent = (agent_of_run.get(agent_run) if agent_run else None) \
                or ev.get("agent") or "?"
            action = ev.get("tool", "?")
            principal = (ev["principal"] if "principal" in ev
                         else principal_of_task.get(task_id, ""))
            trace.tool_call(task_id, agent, action, ev.get("args") or {},
                            source=ev.get("source", "user"),
                            principal=principal,
                            expires_at=expires_of_task.get(task_id))
            tool_runs[rid] = {"task_id": task_id, "agent": agent,
                              "action": action, "principal": principal}
        elif etype == "tool_result":
            if rid in delegation_runs:
                # Results for handoff tool runs carry no action and are
                # ignored (schema); they are not unpaired anomalies.
                continue
            info = tool_runs.get(rid)
            if info is None:
                # Unpaired result: no tool_call was ever observed for
                # this run. Surface it as a trace-visible anomaly — a
                # synthetic tool_call on the uncorrelated task — so the
                # oracle judges it (V5 origin loss) instead of the run
                # reading as clean. The action is taken from the result
                # event when the adapter knows it, else "unknown"; the
                # source marks the synthetic origin.
                action = ev.get("action") or "unknown"
                principal = ev.get("principal") or ""
                trace.tool_call(UNCORRELATED, ev.get("agent") or "?",
                                action, {}, source="tool_result",
                                principal=principal)
                info = {"task_id": UNCORRELATED,
                        "agent": ev.get("agent") or "?",
                        "action": action, "principal": principal}
            if ev.get("ok", True):
                result = str(ev.get("result", ""))[:500]
            else:
                result = f"ERROR: {ev.get('error')}"
            trace.tool_result(info["task_id"], info["agent"],
                              info["action"], result,
                              source=ev.get("source", "user"),
                              principal=(ev["principal"]
                                         if "principal" in ev
                                         else info["principal"]))
    return trace


def run_oracle(trace: Trace, grant: dict) -> Verdict:
    """Judge a rebuilt trace against the user grant."""
    return evaluate(trace, grant)
