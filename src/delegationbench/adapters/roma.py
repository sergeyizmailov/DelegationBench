"""ROMA (roma-dspy) adapter: observe a ROMA v2 run, rebuild the delegation
tree, and judge it with the DelegationBench oracle.

Clean-room notice
-----------------
ROMA has **no LICENSE file** at the audited commit
(``a6e3bb4``); its README claims Apache-2.0 against a missing file. Until
upstream resolves this, treat ROMA as all-rights-reserved. This adapter
therefore interacts with ROMA **only through public runtime interfaces**
(DSPy callbacks, the public solver API, ``solver.last_dag``). It contains
no copied or derived ROMA code, ROMA is not vendored, and ROMA is **not**
a declared dependency of DelegationBench — this module imports and its
tests pass without ROMA or DSPy installed.

Installation
------------
Install ROMA manually, pinned to the audited line, in your own
environment (not in this project's dependency set)::

    pip install "roma-dspy @ git+https://github.com/sentient-agi/ROMA.git@a6e3bb4"

This installs ``dspy>=3`` alongside it. Pin a known-good DSPy version:
ROMA declares no upper bound and the callback API may drift.

Usage
-----
Register the callback before the run; ROMA preserves externally
configured callbacks when invoking its modules::

    import dspy
    from delegationbench.adapters.roma import ROMATraceCallback, build_trace, run_oracle

    cb = ROMATraceCallback()
    dspy.settings.configure(callbacks=[*(dspy.settings.callbacks or []), cb])

    # Side-channel authority map: ROMA does NOT propagate metadata to
    # subtasks, so the harness registers each task as it is created.
    # Observe subtask births either via a class-level patch of
    # ModuleRuntime._create_subtask_graph or post-hoc by walking
    # solver.last_dag (every TaskNode has task_id / parent_id / depth).
    cb.register_task(root_task_id, parent_task_id=None, agent="orchestrator",
                     scope=["docs.read"], task=goal)
    # ... for each subtask:
    cb.register_task(sub.task_id, parent_task_id=sub.parent_id,
                     agent=sub.task_type, scope=[...], depth=sub.depth)

    answer = solve(goal)  # or async_solve / event_solve

    grant = {"allowed_actions": ["docs.read"], "max_delegation_depth": 2,
             "task_id": root_task_id}
    trace = build_trace(cb.events, grant)
    verdict = run_oracle(trace, grant)

Known ROMA trace gaps (from the audit, docs/research/roma-integration.md)
-------------------------------------------------------------------------
- ROMA's own ``ToolInvocationEvent`` records carry **no task_id**; this
  adapter correlates tool calls to tasks via a context-keyed module
  stack (one stack per ``asyncio`` execution context, so interleaved
  sibling tasks attribute to their own module invocation). Calls with no
  module context visible fall back to the ``"uncorrelated"`` sentinel
  and are judged as V5 origin loss.
- Module-level execution events (``subtask_created``, ``plan_complete``,
  ``execute_complete``, ``task_transition``) are defined in ROMA's enum
  but **never emitted**; delegation edges are recovered from the side
  channel / ``last_dag`` walk instead.
- The event-driven execution mode (``event_solve``) emits no per-task
  events at all; the side channel is the only delegation source there.
- DSPy does not guarantee ``on_tool_end`` pairing under exceptions
  (ROMA's own callback keeps a stale-call sweeper); unpaired ends are
  recorded against ``"uncorrelated"`` rather than dropped silently.
"""

from __future__ import annotations

import contextvars
from typing import TYPE_CHECKING, Any

from ..oracle import Verdict, evaluate
from ..trace import Trace
from . import UNCORRELATED, AdapterEvent

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import
    import dspy  # noqa: F401


def _depths(events: list[AdapterEvent]) -> dict[str, int]:
    """Resolve delegation depths: explicit ``depth`` wins, else derive from
    the parent chain (root = 0). Unknown parents yield 0."""
    parent_of = {e.task_id: e.parent_task for e in events
                 if e.kind == "delegation"}
    explicit = {e.task_id: e.depth for e in events
                if e.kind == "delegation" and e.depth is not None}
    depths: dict[str, int] = {}

    def depth_of(task_id: str, seen: frozenset[str] = frozenset()) -> int:
        if task_id in explicit:
            return explicit[task_id]
        if task_id in depths:
            return depths[task_id]
        parent = parent_of.get(task_id)
        if parent is None or parent in seen or parent not in parent_of:
            return 0
        return depth_of(parent, seen | {task_id}) + 1

    for task_id in parent_of:
        depths[task_id] = depth_of(task_id)
    return depths


def _order_events(events: list[AdapterEvent]) -> list[AdapterEvent]:
    """Normalize capture order into trace order.

    Post-hoc capture (the ROMA example registers the task DAG *after*
    execution) interleaves tool events with the delegation events that
    authorize them, so a tool call can precede its task's delegation and
    be judged V5 despite being authorized. Reorder so that every task's
    delegation event precedes any of its tool events and delegations are
    topological (parents before children, by resolved depth; stable for
    equal depths). Non-delegation events keep their relative order.
    """
    depths = _depths(events)
    delegations = sorted((e for e in events if e.kind == "delegation"),
                         key=lambda e: depths[e.task_id])
    others = [e for e in events if e.kind != "delegation"]
    return delegations + others


def build_trace(events: list[AdapterEvent], grant: dict) -> Trace:
    """Convert captured adapter events into a DelegationBench Trace.

    The root delegation is synthesized from ``grant``: if ``events``
    contain a delegation with ``parent_task=None`` it is used as the root
    (its requested scope is recorded; the oracle intersects it with the
    grant anyway). Otherwise a synthetic root is emitted with
    ``grant.get("task_id", "root")``, agent ``grant.get("agent", "root")``
    and scope = ``grant["allowed_actions"]``.

    Event order is normalized before conversion (see :func:`_order_events`):
    delegation events come first, parents before children, so tool calls
    captured before their task's delegation registration are still judged
    against that delegation instead of reading as V5 origin loss.
    """
    trace = Trace()
    has_root = any(e.kind == "delegation" and e.parent_task is None
                   for e in events)
    if not has_root:
        trace.delegation(None, grant.get("task_id", "root"),
                         grant.get("agent", "root"),
                         sorted(grant["allowed_actions"]), depth=0,
                         nonce=grant.get("nonce", "n-root"),
                         expires_at=None, source="user",
                         task=grant.get("task", ""))
    depths = _depths(events)
    for e in _order_events(events):
        if e.time is not None:
            trace.clock.now = e.time
        if e.kind == "delegation":
            trace.delegation(e.parent_task, e.task_id, e.agent,
                             sorted(e.scope), depth=depths[e.task_id],
                             nonce=e.nonce, expires_at=e.expires_at,
                             source=e.source, task=e.task, args=e.args)
        elif e.kind == "tool_call":
            trace.tool_call(e.task_id, e.agent, e.action, e.args,
                            source=e.source, nonce=e.nonce,
                            expires_at=e.expires_at)
        elif e.kind == "tool_result":
            trace.tool_result(e.task_id, e.agent, e.action, e.result,
                              source=e.source)
        else:
            raise ValueError(f"unknown adapter event kind: {e.kind!r}")
    return trace


def run_oracle(trace: Trace, grant: dict) -> Verdict:
    """Judge a built trace against the user grant."""
    return evaluate(trace, grant)


class ROMATraceCallback:
    """DSPy-style callback capturing ROMA tool traffic as adapter events.

    Duck-typed: it implements the ``on_tool_start`` / ``on_tool_end`` /
    ``on_module_start`` / ``on_module_end`` hooks DSPy ≥3 calls on every
    registered callback, without importing DSPy. Register it in
    ``dspy.settings.callbacks`` before the run (ROMA preserves external
    callbacks). If your DSPy version enforces ``BaseCallback``
    inheritance, use :func:`dspy_callback_class` instead.

    Correlation strategy: ROMA tool records carry no task_id, so this
    callback keeps a stack of active module contexts per *execution
    context* (``contextvars.ContextVar``). ``on_module_start`` inspects
    the module inputs for a task object (anything with a string
    ``task_id`` attribute, or a ``task_id`` key — ROMA executors receive
    the ``TaskNode``), pushes it keyed by the module's ``call_id``, and
    ``on_module_end`` pops that same ``call_id``'s frame. Tool calls are
    attributed to the innermost active task *of their own context*.

    Because ROMA runs sibling subtasks via ``asyncio.gather``, each
    sibling coroutine inherits its own copy of the context: a module
    start in sibling B never clobbers sibling A's stack, so interleaved
    siblings (start A, start B, tool from A) attribute correctly. A
    single global stack would misattribute that tool call to B — wrong
    attribution is worse than none, so a tool call whose context has no
    active module frame is recorded under ``"uncorrelated"`` (the oracle
    judges these as V5 origin loss) rather than guessed.

    Limits: correlation is only as good as the context boundary. True
    interleaving *within one* context (e.g. threads sharing a context,
    or a framework that drives siblings sequentially in one coroutine
    without call_id-discernible nesting) is indistinguishable from
    nesting and falls back to stack-top attribution; DSPy's callback API
    passes no parent run identifier that would let the adapter do better.
    """

    def __init__(self) -> None:
        self.events: list[AdapterEvent] = []
        # Side-channel authority map, keyed by task_id. ROMA does not
        # propagate metadata to subtasks, so the harness populates this as
        # tasks are created.
        self.authority: dict[str, dict[str, Any]] = {}
        # Active task ids of the current execution context (innermost
        # last). Stored as an immutable tuple so every push/pop sets a
        # fresh value — required for per-coroutine isolation.
        self._task_stack: contextvars.ContextVar[tuple[str, ...]] = (
            contextvars.ContextVar("delegationbench_roma_task_stack",
                                   default=()))
        self._module_calls: dict[Any, str] = {}   # call_id -> task_id
        self._pending_tools: dict[Any, AdapterEvent] = {}

    # -- side-channel authority map -------------------------------------

    def register_task(self, task_id: str, parent_task_id: str | None,
                      agent: str, scope, *, source: str = "user",
                      depth: int | None = None, nonce: str = "",
                      expires_at: float | None = None,
                      task: str = "") -> None:
        """Register a ROMA task at birth (see module docstring).

        Emits a ``delegation`` adapter event; the oracle re-derives
        effective authority from it, so the registered scope is the
        *requested* scope, not proof of authority.
        """
        self.authority[task_id] = {
            "parent_task_id": parent_task_id, "agent": agent,
            "scope": frozenset(scope), "depth": depth, "nonce": nonce,
            "expires_at": expires_at,
        }
        self.events.append(AdapterEvent(
            "delegation", task_id, parent_task=parent_task_id, agent=agent,
            scope=tuple(sorted(scope)), source=source, depth=depth,
            nonce=nonce, expires_at=expires_at, task=task))

    # -- DSPy callback hooks --------------------------------------------

    @staticmethod
    def _task_id_from_inputs(inputs: Any) -> str | None:
        if isinstance(inputs, dict):
            for value in inputs.values():
                task_id = getattr(value, "task_id", None)
                if isinstance(task_id, str):
                    return task_id
            task_id = inputs.get("task_id")
            if isinstance(task_id, str):
                return task_id
        return None

    def on_module_start(self, call_id, instance, inputs) -> None:
        task_id = self._task_id_from_inputs(inputs)
        if task_id is not None:
            self._module_calls[call_id] = task_id
            self._task_stack.set(self._task_stack.get() + (task_id,))

    def on_module_end(self, call_id, outputs=None, exception=None) -> None:
        task_id = self._module_calls.pop(call_id, None)
        if task_id is not None:
            stack = self._task_stack.get()
            if task_id in stack:
                # Pop the innermost matching frame; nested calls with the
                # same task keep the outer frames intact.
                idx = len(stack) - 1 - stack[::-1].index(task_id)
                self._task_stack.set(stack[:idx] + stack[idx + 1:])

    def on_tool_start(self, call_id, instance, inputs) -> None:
        name = (getattr(instance, "__name__", None)
                or getattr(instance, "name", None)
                or type(instance).__name__)
        stack = self._task_stack.get()
        # Attribute to this context's innermost module invocation. With
        # no frame visible in THIS context the call is genuinely
        # unattributable: record "uncorrelated" (V5-detectable) instead
        # of guessing a task from another context.
        task_id = stack[-1] if stack else UNCORRELATED
        meta = self.authority.get(task_id, {})
        event = AdapterEvent(
            "tool_call", task_id,
            agent=meta.get("agent", ""),
            source="user",
            action=name,
            args=dict(inputs) if isinstance(inputs, dict) else {},
            nonce=meta.get("nonce", ""),
            expires_at=meta.get("expires_at"))
        self._pending_tools[call_id] = event
        self.events.append(event)

    def on_tool_end(self, call_id, outputs=None, exception=None) -> None:
        start = self._pending_tools.pop(call_id, None)
        if start is None:
            # Unpaired end (DSPy does not guarantee pairing under
            # exceptions): keep it visible as origin loss rather than
            # dropping it.
            start = AdapterEvent("tool_call", UNCORRELATED, action="unknown")
        result = f"error: {exception}" if exception is not None else str(outputs)
        self.events.append(AdapterEvent(
            "tool_result", start.task_id, agent=start.agent,
            source=start.source, action=start.action, result=result))

    # -- convenience -----------------------------------------------------

    def build_trace(self, grant: dict) -> Trace:
        """Build a Trace from everything captured so far."""
        return build_trace(self.events, grant)

    def run_oracle(self, grant: dict) -> Verdict:
        """Build the trace and judge it in one call."""
        return run_oracle(self.build_trace(grant), grant)


def dspy_callback_class() -> type:
    """Return a ROMATraceCallback subclass of ``dspy``'s ``BaseCallback``.

    Imported lazily; only needed if the installed DSPy version enforces
    inheritance instead of duck-typing the hooks.
    """
    import dspy  # noqa: F401 — lazy: dspy is an optional, manual install
    from dspy.utils.callback import BaseCallback

    class ROMATraceDSPyCallback(ROMATraceCallback, BaseCallback):
        pass

    return ROMATraceDSPyCallback
