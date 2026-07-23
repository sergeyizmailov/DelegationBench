"""LangGraph adapter for DelegationBench.

Observes a compiled LangGraph graph through the LangChain callback
machinery and emits the neutral events defined in
:mod:`delegationbench.adapters`, which :func:`build_trace` then maps
into a :class:`~delegationbench.trace.Trace` for the oracle.

Usage (no framework or application source changes — attach at invoke
time)::

    from delegationbench.adapters.langgraph import (
        DelegationBenchCallback, build_trace, run_oracle)

    handler = DelegationBenchCallback(agents={"reader", "payment"})
    result = await graph.ainvoke(
        inputs,
        config={
            "callbacks": [handler],
            "configurable": {"thread_id": "t-1"},
            # Principal carrier: LangGraph has no built-in user identity,
            # so the harness MUST inject it here. config["metadata"]
            # propagates to every child run's callback metadata.
            "metadata": {"principal": "user-123"},
        },
    )
    grant = {"allowed_actions": ["docs.read"], "max_delegation_depth": 2,
             "principal": "user-123"}
    trace = build_trace(handler.events, grant)
    verdict = run_oracle(trace, grant)

The harness also owns the root grant: the adapter maps the first
ancestral agent run into the root delegation holding
``grant["allowed_actions"]``; everything below it is reconstructed from
the run hierarchy.

Event mapping
-------------
- ``on_chain_start`` with ``metadata["langgraph_node"]`` -> ``agent_start``
  (``metadata["checkpoint_ns"]`` marks subgraph namespaces but is not
  needed for the tree; ``parent_run_id`` chains suffice).
- ``on_tool_start`` -> ``tool_call``, or ``delegation`` when the tool is
  a handoff: name starts with ``transfer_to_``/``delegate_to_``
  (langgraph-supervisor default, docs convention), or the destination is
  stamped under ``__handoff_destination`` in tool/run metadata
  (langgraph-supervisor's ``METADATA_KEY_HANDOFF_DESTINATION``).
- ``on_tool_end`` / ``on_tool_error`` -> ``tool_result`` (``ok``
  true/false). Handoff tool results carry no action and are dropped by
  ``build_trace``.
- Agent identity for a tool run = nearest ancestor run with a
  ``langgraph_node``; principal = ``config["metadata"]["principal"]``
  (or ``user_id``) seen on any run's metadata, stamped on EVERY emitted
  event (agent runs, delegations, tool calls and results) so
  ``build_trace`` can populate the trace's first-class
  ``Event.principal`` and the oracle can judge V7.

Version context
---------------
Targets the LangGraph 1.x / langchain-core 1.x callback API
(``AsyncCallbackHandler`` hook signatures stable since 2023; researched
against langgraph 1.2.9 / langchain-core 1.5.0, 2026-07 — see
``docs/research/langgraph-integration.md``). ``langgraph`` is an
optional dependency: this module imports cleanly without it, and only
subclasses ``langchain_core.callbacks.AsyncCallbackHandler`` when
langchain_core is importable (otherwise it is duck-typed with identical
async methods). Install with ``pip install 'delegationbench[langgraph]'``.

Known gaps
----------
- ``tool_call_id`` is not passed to ``on_tool_start``
  (langchain-ai/langchain#34168): correlation is by ``run_id`` only.
- Handoff detection is naming/metadata-convention based. Custom
  ``StateGraph`` graphs whose delegations are plain edges or
  differently-named tools need ``handoff_prefixes``/``agents`` tuning
  or per-scenario rules.
- No principal identity exists in-framework; without harness-injected
  ``config["metadata"]["principal"]`` the originating user is
  unrecoverable from events.
- Framework handoffs carry no task *scope*, so a child delegation's
  scope defaults to the parent's authority: V1 (authority expansion on
  handoff) cannot be observed unless the harness supplies ``scope`` in
  the delegation event args out-of-band.
- Async-only handler: attach to ``ainvoke``/``astream``. Synchronous
  ``invoke`` would need a ``BaseCallbackHandler`` variant with the same
  recording logic.
"""

from __future__ import annotations

import time
from typing import Any, Iterable

from . import NeutralEvent, build_trace, run_oracle

__all__ = ["DelegationBenchCallback", "NeutralEvent", "build_trace",
           "run_oracle"]

try:  # Real base class when langchain_core is installed.
    from langchain_core.callbacks import (
        AsyncCallbackHandler as _AsyncCallbackHandler)
except Exception:  # langchain not installed: duck-typed stand-in.
    _AsyncCallbackHandler = object


class DelegationBenchCallback(_AsyncCallbackHandler):
    """AsyncCallbackHandler that records neutral DelegationBench events.

    Parameters
    ----------
    agents:
        Node names to treat as agents. ``None`` (default) treats every
        chain run carrying ``metadata["langgraph_node"]`` as an agent
        run. Pass an explicit set to ignore infrastructure nodes
        (routers, tool nodes) in larger graphs.
    principal_keys:
        Metadata keys probed, in order, for the originating-user id.
        Default: ``("principal", "user_id")``.
    handoff_prefixes:
        Tool-name prefixes that mark a delegation handoff. Default:
        ``("transfer_to_", "delegate_to_")``. The langgraph-supervisor
        ``__handoff_destination`` metadata key is always honored.
    action_map:
        Application-supplied mapping from framework tool names to
        canonical grant actions, e.g. ``{"read_doc": "docs.read",
        "execute_payment": "payment.execute"}``. Real framework tools are
        named like Python functions while grants use canonical action
        ids, so without this mapping the oracle judges every tool call
        on its raw name (an authorized ``read_doc`` under a
        ``docs.read`` grant reads as V2). Tool names not present in the
        map pass through **unchanged** — that pass-through is deliberate:
        the oracle then judges the raw name, which surfaces unmapped
        tools as V2 instead of silently authorizing them. Handoff
        (delegation) tool names are never mapped.
    handoffs:
        Exact custom handoff definitions keyed by tool name. A value may
        be a destination-agent string or a mapping with ``to_agent`` and
        optional ``scope`` / ``task``. Exact definitions take precedence
        over naming conventions and make custom handoffs auditable.
    """

    HANDOFF_PREFIXES = ("transfer_to_", "delegate_to_")
    HANDOFF_METADATA_KEY = "__handoff_destination"
    PRINCIPAL_KEYS = ("principal", "user_id")

    def __init__(self, agents: Iterable[str] | None = None,
                 principal_keys: Iterable[str] | None = None,
                 handoff_prefixes: Iterable[str] | None = None,
                 action_map: dict[str, str] | None = None,
                 handoffs: dict[str, str | dict] | None = None) -> None:
        self.agents = set(agents) if agents is not None else None
        self.principal_keys = tuple(principal_keys or self.PRINCIPAL_KEYS)
        self.handoff_prefixes = tuple(handoff_prefixes
                                      or self.HANDOFF_PREFIXES)
        self.action_map = dict(action_map or {})
        self.handoffs = dict(handoffs or {})
        self.events: list[NeutralEvent] = []
        self._agent_of_run: dict[str, str] = {}
        self._parent_of_run: dict[str, str | None] = {}
        self._principal_of_run: dict[str, Any] = {}
        self._run_principal: Any = None  # last principal seen anywhere

    # -- internal helpers ------------------------------------------------

    def _record_run(self, run_id: Any, parent_run_id: Any) -> None:
        self._parent_of_run[str(run_id)] = (
            str(parent_run_id) if parent_run_id else None)

    def _nearest_agent(self, run_id: Any) -> str | None:
        rid = str(run_id) if run_id else None
        seen: set[str] = set()
        while rid is not None and rid not in seen:
            seen.add(rid)
            if rid in self._agent_of_run:
                return rid
            rid = self._parent_of_run.get(rid)
        return None

    def _principal(self, metadata: dict | None) -> Any:
        for key in self.principal_keys:
            if metadata and key in metadata:
                return metadata[key]
        return None

    def _event_principal(self, metadata: dict | None,
                         run_id: Any = None) -> Any:
        """Best principal for an event: the run's own metadata, else the
        principal recorded for this run, else the run-level default
        (``config["metadata"]`` propagates to every child run, so in
        practice one principal covers the whole invocation)."""
        principal = self._principal(metadata)
        if principal is not None:
            if run_id is not None:
                self._principal_of_run[str(run_id)] = principal
            self._run_principal = principal
            return principal
        if run_id is not None and str(run_id) in self._principal_of_run:
            return self._principal_of_run[str(run_id)]
        return self._run_principal

    def record_handoff(self, *, run_id: Any, parent_run_id: Any,
                       from_agent: str, to_agent: str, scope,
                       principal: str, task: str = "",
                       child_run_id: Any = None,
                       source: str = "user",
                       args: dict | None = None) -> None:
        """Record an explicit custom/parallel delegation.

        Use this for plain LangGraph edges, ``Send`` fan-out, or custom
        routing that does not execute a recognizable handoff tool.
        ``child_run_id`` gives deterministic correlation when multiple
        siblings target the same agent concurrently.
        """
        rid = str(run_id)
        parent = str(parent_run_id) if parent_run_id is not None else None
        event: NeutralEvent = {
            "type": "delegation", "run_id": rid,
            "parent_run_id": parent, "from_agent": from_agent,
            "to_agent": to_agent, "tool": "explicit_handoff",
            "scope": list(scope), "principal": principal,
            "task": task, "source": source, "args": dict(args or {}),
            "ts": time.time(),
        }
        if child_run_id is not None:
            event["child_run_id"] = str(child_run_id)
        self.events.append(event)

    # -- callback hooks ---------------------------------------------------

    async def on_chain_start(self, serialized: dict | None,
                             inputs: Any, *, run_id: Any,
                             parent_run_id: Any = None,
                             tags: list[str] | None = None,
                             metadata: dict | None = None,
                             **kwargs: Any) -> None:
        self._record_run(run_id, parent_run_id)
        metadata = metadata or {}
        node = metadata.get("langgraph_node")
        if not node or (self.agents is not None and node not in self.agents):
            return
        rid = str(run_id)
        self._agent_of_run[rid] = node
        event: NeutralEvent = {
            "type": "agent_start", "run_id": rid,
            "parent_run_id": str(parent_run_id) if parent_run_id else None,
            "agent": node, "ts": time.time(),
        }
        explicit_task = metadata.get("delegation_task_id")
        if explicit_task is not None:
            event["task_id"] = str(explicit_task)
        principal = self._event_principal(metadata, run_id)
        if principal is not None:
            event["principal"] = principal
        self.events.append(event)

    async def on_chain_end(self, outputs: Any, *, run_id: Any,
                           **kwargs: Any) -> None:
        rid = str(run_id)
        if rid in self._agent_of_run:
            self.events.append({"type": "agent_end", "run_id": rid,
                                "agent": self._agent_of_run[rid],
                                "ts": time.time()})

    async def on_tool_start(self, serialized: dict | None, input_str: str,
                            *, run_id: Any, parent_run_id: Any = None,
                            tags: list[str] | None = None,
                            metadata: dict | None = None,
                            inputs: dict | None = None,
                            **kwargs: Any) -> None:
        self._record_run(run_id, parent_run_id)
        metadata = metadata or {}
        serialized = serialized or {}
        name = serialized.get("name") or "?"
        custom = self.handoffs.get(name)
        custom_spec = custom if isinstance(custom, dict) else {}
        custom_dest = (custom if isinstance(custom, str)
                       else custom_spec.get("to_agent"))
        dest = custom_dest or (serialized.get("metadata") or {}).get(
            self.HANDOFF_METADATA_KEY) or metadata.get(
            self.HANDOFF_METADATA_KEY)
        is_handoff = dest is not None or name.startswith(
            self.handoff_prefixes)
        rid = str(run_id)
        from_run = self._nearest_agent(parent_run_id)
        from_agent = (self._agent_of_run.get(from_run) if from_run
                      else None)
        # Anchor the event to the nearest ancestor AGENT run rather than
        # the raw parent run: in real graphs the raw parent is an
        # infrastructure node run (ToolNode, "tools") that emits no
        # event, so build_trace could not walk past it. The full raw
        # tree is only needed internally; downstream consumers reason
        # about agent runs.
        parent = from_run or (str(parent_run_id) if parent_run_id
                              else None)
        principal = self._event_principal(metadata, run_id)
        if is_handoff:
            if dest is None:
                for prefix in self.handoff_prefixes:
                    if name.startswith(prefix):
                        dest = name[len(prefix):]
                        break
            event: NeutralEvent = {
                "type": "delegation", "run_id": rid,
                "parent_run_id": parent, "from_agent": from_agent,
                "to_agent": dest, "tool": name,
                "args": dict(inputs or {}), "ts": time.time(),
            }
            scope = custom_spec.get("scope")
            if scope is None:
                scope = (inputs or {}).get("scope")
            if scope is None:
                scope = metadata.get("delegation_scope")
            if scope is not None:
                event["scope"] = list(scope)
            task = (custom_spec.get("task")
                    or (inputs or {}).get("task")
                    or metadata.get("delegation_task"))
            if task is not None:
                event["task"] = str(task)
            child_run_id = ((inputs or {}).get("child_run_id")
                            or metadata.get("delegation_child_run_id"))
            if child_run_id is not None:
                event["child_run_id"] = str(child_run_id)
            event["source"] = metadata.get("delegation_source", "user")
            if principal is not None:
                event["principal"] = principal
            self.events.append(event)
        else:
            # Map the framework tool name to the canonical grant action;
            # unmapped names pass through unchanged (see class docstring).
            action = self.action_map.get(name, name)
            event = {
                "type": "tool_call", "run_id": rid, "parent_run_id": parent,
                "agent": from_agent or metadata.get("langgraph_node"),
                "tool": action, "args": dict(inputs or {}),
                "source": metadata.get("delegation_source", "user"),
                "ts": time.time(),
            }
            if principal is not None:
                event["principal"] = principal
            self.events.append(event)

    async def on_tool_end(self, output: Any, *, run_id: Any,
                          **kwargs: Any) -> None:
        event: NeutralEvent = {"type": "tool_result",
                               "run_id": str(run_id),
                               "ok": True, "result": str(output)[:500],
                               "ts": time.time()}
        principal = self._event_principal(None, run_id)
        if principal is not None:
            event["principal"] = principal
        self.events.append(event)

    async def on_tool_error(self, error: BaseException, *, run_id: Any,
                            **kwargs: Any) -> None:
        event: NeutralEvent = {"type": "tool_result",
                               "run_id": str(run_id),
                               "ok": False, "error": str(error),
                               "ts": time.time()}
        principal = self._event_principal(None, run_id)
        if principal is not None:
            event["principal"] = principal
        self.events.append(event)
