# DelegationBench — LangGraph Integration Research

## Executive Summary

LangGraph is a strong second target for DelegationBench. All three required observation
capabilities — delegation/handoff events, tool calls with arguments, and principal context —
are obtainable **without modifying framework source**, via the LangChain callback/tracer
machinery that LangGraph inherits (`BaseCallbackHandler` / `astream_events` v2). Delegations
in LangGraph are not a separate primitive: they are ordinary tool calls (`transfer_to_<agent>`)
whose result is a `Command(goto=...)`, which makes them trivially visible as tool events and
correlatable through the `run_id` / `parent_run_id` hierarchy. The main gap: LangGraph has
**no built-in notion of an originating user/principal** — identity must be smuggled in through
`RunnableConfig.metadata` (which propagates to every child event) or mapped from
`configurable.thread_id`. **Recommended primary mechanism: a custom
`AsyncCallbackHandler` attached at invoke-time via `config={"callbacks": [...]}`** (equivalent
coverage to `astream_events` v2, but push-based and works with plain `.invoke()`); the newer
LangChain 1.0 agent middleware API is a useful enrichment layer when the harness builds agents
with `create_agent` and allows middleware injection.

## Scope

- **Research date:** 2026-07-23 (recorded via `date` at session start).
- **Framework:** LangGraph Python (`langchain-ai/langgraph`), plus `langchain` 1.x agent layer
  and `langgraph-supervisor`.
- **Versions current at research date** (PyPI):
  - `langgraph` **1.2.9** (released 2026-07-10)
  - `langchain` **1.3.14** (released 2026-07-16)
  - `langchain-core` **1.5.0** (released 2026-07-21)
  - `langgraph-supervisor` **0.0.31** (released 2025-11-19)
- LangGraph 1.0 and LangChain 1.0 went GA on **2025-10-22**; LangGraph 1.0 claimed zero
  breaking changes from late 0.x.

## Findings

### 1. Multi-agent patterns and where delegation becomes observable

Current docs ([Multi-agent overview](https://docs.langchain.com/oss/python/langchain/multi-agent))
list five patterns: **Subagents** (main agent calls subagents as tools), **Handoffs**,
**Skills**, **Router**, **Custom workflow**. The DelegationBench-relevant ones:

- **Supervisor (`langgraph-supervisor`, `create_supervisor`)** — wraps worker agents into a
  routing graph. The supervisor LLM delegates by calling auto-generated handoff tools named
  `transfer_to_<agent_name>` (prefix customizable, e.g. `delegate_to_`). Source:
  [`langgraph_supervisor/handoff.py`](https://raw.githubusercontent.com/langchain-ai/langgraph-supervisor-py/main/langgraph_supervisor/handoff.py)
  — `create_handoff_tool()` builds a `@tool` that returns
  `Command(goto=agent_name, graph=Command.PARENT, update={...messages...})` and stamps the
  destination in two places:
  - `handoff_to_agent.metadata = {METADATA_KEY_HANDOFF_DESTINATION: agent_name}`
    (`"__handoff_destination"`) on the tool object, and
  - `ToolMessage.response_metadata["__handoff_destination"]` on the handoff result message.
  Return-to-supervisor is marked with `METADATA_KEY_IS_HANDOFF_BACK = "__is_handoff_back"`.
- **Handoffs pattern (LangChain 1.x)** — handoff tools update a state variable
  (`active_agent` / `current_step`) and/or route via `Command(goto=..., graph=Command.PARENT)`
  between agent subgraphs
  ([Handoffs guide](https://docs.langchain.com/oss/python/langchain/multi-agent/handoffs)).
  Two sub-variants: single agent + middleware switching config, or multiple agent subgraphs
  in one `StateGraph`.
- **Subagents-as-tools** — a child agent is invoked inside a tool call; observable as a tool
  call whose execution spawns a nested agent run (visible as child `run_id`s).
- **Custom `StateGraph`** — agents are plain nodes; "delegation" is just graph edges /
  `Command(goto=...)`. Only node-level events are available; semantic intent must be inferred
  from node names and `Command` targets.

**Where a handoff becomes observable:** a delegation is always materialized as (a) an
`AIMessage.tool_calls` entry naming `transfer_to_*` (or a custom handoff tool), then (b) a
tool execution event carrying the destination in tool metadata / `ToolMessage`
`response_metadata`, then (c) a node transition (`Command.goto`). All three surfaces are
externally visible — no source patching needed.

### 2. Interception mechanisms

| Mechanism | Attach point | Coverage | Notes |
|---|---|---|---|
| **Callbacks / tracers** — `langchain_core.callbacks.BaseCallbackHandler` / `AsyncCallbackHandler` | Invoke-time: `graph.invoke(input, config={"callbacks": [handler]})` — no construction-time access needed | Node (chain) start/end, tool start/end/error, model calls, full `run_id`/`parent_run_id` tree, tags, propagated metadata | Same machinery that powers LangSmith tracing. Works on any compiled graph. |
| **Streaming events** — `Runnable.astream_events(input, version="v2")` | Wrap the invocation call | Identical event set (`on_chain_*`, `on_tool_*`, `on_chat_model_*`, `on_custom_event`) as a pull stream; `parent_ids` list (v2 only) | Requires consuming the stream instead of a plain result; LangGraph injects `metadata.langgraph_node` and `metadata.checkpoint_ns` into events. |
| **Agent middleware** — `langchain.agents.middleware.AgentMiddleware` | Construction-time: `create_agent(..., middleware=[...])` | Richest per-hook data: `before_agent`, `before_model`, `after_model`, `after_agent` (node-style) and `wrap_model_call`, `wrap_tool_call` (wrap-style, with `ToolCallRequest` / `ModelRequest` objects incl. args, state, runtime) | New in LangChain 1.0. Only applies to `create_agent`-built agents; **does not** fire for hand-rolled `StateGraph` nodes or arbitrary graphs. Requires harness cooperation at agent build time. |
| **Checkpointers / state inspection** — `graph.get_state(config)`, `graph.get_state_history(config)` | Post-hoc, any time | Full state snapshots incl. `messages` (so handoff ToolMessages with `__handoff_destination` are recoverable) | Good for audit/forensics and cross-checking, not for real-time interposition. |

**Most complete tool-call + delegation trace:** callbacks/`astream_events` v2 (they are the
same event pipeline) — universal across graph styles, invoke-time attachable, and they carry
the run hierarchy needed to rebuild delegation trees. Middleware adds richer payloads but is
narrower in applicability.

### 3. What an adapter can capture — exact hooks/APIs and version applicability

- **Node/agent start & end:** `on_chain_start(serialized, inputs, *, run_id, parent_run_id, tags, metadata, ...)` /
  `on_chain_end(outputs, *, run_id, ...)` on `BaseCallbackHandler`
  ([reference](https://reference.langchain.com/python/langchain-core/callbacks/base/CallbackManagerMixin/on_chain_start)).
  In event streams: `on_chain_start` / `on_chain_end` with `metadata["langgraph_node"]` =
  node name and `metadata["checkpoint_ns"]` = subgraph namespace
  ([`astream_events` reference](https://reference.langchain.com/python/langchain-core/runnables/base/Runnable/astream_events)).
  Applicability: all `langchain-core` ≥ 0.1; v2 event schema (incl. `parent_ids`) since
  `langchain-core` 0.2; current and canonical in 1.x.
- **Tool call name + args + result:** `on_tool_start(serialized, input_str, *, run_id, parent_run_id, tags, metadata, inputs, ...)`
  (`inputs` = parsed args dict; note `serialized["name"]` is the tool name) and
  `on_tool_end(output, *, run_id, ...)` / `on_tool_error(error, ...)`
  ([reference](https://reference.langchain.com/python/langchain-core/callbacks/base/CallbackManagerMixin/on_tool_start)).
  Event-stream equivalents `on_tool_start` (`data.input`) / `on_tool_end` (`data.output`).
  Known wart: `tool_call_id` is not passed to `on_tool_start` (langchain-ai/langchain#34168)
  — correlate via `run_id` instead. Middleware alternative: `@wrap_tool_call(request, handler)`
  with `request.tool_call` (name + args) and the handler's `ToolMessage | Command` return —
  LangChain ≥ 1.0, `create_agent` only
  ([custom middleware docs](https://docs.langchain.com/oss/python/langchain/middleware/custom)).
- **Messages between agents:** full message history is in graph state — `on_chain_end`
  outputs for agent nodes, checkpoint state (`graph.get_state`), or `stream_mode="messages"`.
  Handoff markers: `ToolMessage.response_metadata["__handoff_destination"]` and
  `AIMessage.name` (agent attribution, via `with_agent_name`).
- **Thread / user context:** `config["configurable"]["thread_id"]` scopes a conversation;
  arbitrary `config["metadata"]` (e.g. `{"user_id": ..., "roles": ...}`) set at invoke-time
  **propagates to every child run** and appears in each callback/event's `metadata` — this is
  the viable principal-carrier. LangGraph 1.0's runtime context (`context=` param,
  `runtime.context` in tools/middleware) is accessible inside user code but is **not**
  surfaced in callback/event metadata, so it cannot serve as the observation channel alone.

### 4. Reconstructing a delegation tree

- Every event carries `run_id` + `parent_run_id` (callbacks) / `parent_ids` (events v2),
  ordered root → immediate parent. The run tree is exactly the delegation tree's skeleton:
  root graph run → supervisor node run → tool run (`transfer_to_researcher`) → child agent
  node run (namespace in `checkpoint_ns`) → its tool runs, etc.
- Edges are labeled by joining: tool run's `serialized.name` / `inputs` (delegation args),
  tool metadata `__handoff_destination` (langgraph-supervisor), or the
  `active_agent`/`current_step` state delta (LangChain 1.x handoffs pattern) /
  `Command.goto` visible in node outputs.
- Subagent-as-tool delegations show as a chain run nested directly under a tool run — same
  `parent_run_id` mechanics.
- **What's missing:**
  - **Originating-user identity** is carried nowhere by default. No `user_id`,
    `principal`, or auth context exists in state, events, or checkpoints. The adapter must
    either require the harness to pass `metadata={"user_id": ...}` at invoke, or maintain an
    out-of-band `thread_id → principal` map (thread IDs appear in `config`, not in events —
    so a metadata-based carrier is the cleaner path).
  - **Semantic intent of custom-graph edges**: for hand-rolled `StateGraph`s, which node
    transition constitutes a "delegation" vs. ordinary control flow needs a per-scenario
    convention (e.g. node names, `Command` targets, handoff-tool naming).
  - Parallel handoffs (`Send` API in langgraph-supervisor) produce sibling runs — handled by
    the same tree logic, but worth a test case.

### 5. Stability / maintenance

- **Release cadence:** very high — `langgraph` 1.2.9 (2026-07-10), `langchain` 1.3.14
  (2026-07-16), `langchain-core` 1.5.0 (2026-07-21); roughly weekly-to-monthly minor/patch
  releases across the 1.x line.
- **Current major:** 1.x for all core packages; GA since 2025-10-22 with an explicit "no
  breaking changes from late 0.x" commitment for LangGraph 1.0.
- **Deprecation risk of relied-upon APIs:**
  - `BaseCallbackHandler` / `AsyncCallbackHandler` hook signatures — **low risk**; stable
    since 2023, load-bearing for LangSmith and the whole tracer ecosystem.
  - `astream_events` — **medium-low**; v1 schema deprecated, v2 is the canonical schema in
    1.x. Pin to `version="v2"`.
  - `Command(goto=..., graph=Command.PARENT)` and tool-returning-`Command` — **low**; core
    LangGraph 1.x routing primitive.
  - Agent middleware (`AgentMiddleware`, `wrap_tool_call`) — **medium**; new in 1.0, still
    evolving (e.g. stream-transformer APIs appeared in later 1.x releases). Use as a
    secondary mechanism only.
  - `langgraph-supervisor` — **medium-high**; still 0.0.x, last release 2025-11-19, built on
    the legacy `create_react_agent` prebuilt. Its handoff metadata keys
    (`__handoff_destination`) are stable in practice but not semver-guaranteed. The
    `create_react_agent` prebuilt itself is superseded by `langchain.agents.create_agent`.
  - General advice: pin minor versions in the bench harness and gate upgrades on the
    adapter's event-capture tests.

### 6. Recommended Adapter Event Schema (framework-neutral)

Minimal event set DelegationBench needs from any framework adapter:

```jsonc
// run boundary — one per agent invocation
{"type": "agent_start", "run_id": "...", "parent_run_id": "...|null",
 "agent": "<node/agent name>", "principal": {"user_id": "...", "thread_id": "..."},
 "ts": "..."}
{"type": "agent_end",   "run_id": "...", "agent": "...", "ts": "..."}

// delegation — derived from handoff tool call / Command goto
{"type": "delegation", "run_id": "<tool run_id>", "parent_run_id": "<delegator run_id>",
 "from_agent": "...", "to_agent": "...", "tool": "transfer_to_researcher",
 "args": {...}, "ts": "..."}

// tool call lifecycle
{"type": "tool_call",   "run_id": "...", "parent_run_id": "...", "agent": "...",
 "tool": "...", "args": {...}, "is_handoff": false, "ts": "..."}
{"type": "tool_result", "run_id": "...", "tool": "...", "ok": true,
 "result_preview": "...", "error": null, "ts": "..."}

// message transfer (optional, for content inspection)
{"type": "message", "run_id": "...", "from_agent": "...", "to_agent": "...",
 "role": "ai|tool", "content_ref": "...", "ts": "..."}
```

`parent_run_id` chains let the bench reconstruct the full delegation tree offline;
`principal` must be injected by the harness via config metadata (see Risks).

### 7. Adapter Sketch (~30 lines, pseudo-code)

```python
from langchain_core.callbacks import AsyncCallbackHandler

HANDOFF_MARKERS = ("transfer_to_", "delegate_to_")   # + tool.metadata["__handoff_destination"]

class DelegationBenchHandler(AsyncCallbackHandler):
    def __init__(self, emit, agents):                # emit: framework-neutral event sink
        self.emit, self.agents, self.runs = emit, agents, {}

    async def on_chain_start(self, serialized, inputs, *, run_id, parent_run_id, metadata, **kw):
        node = metadata.get("langgraph_node")
        if node and node in self.agents:             # agent/node boundary
            self.runs[str(run_id)] = node
            await self.emit({"type": "agent_start", "run_id": str(run_id),
                             "parent_run_id": str(parent_run_id) if parent_run_id else None,
                             "agent": node, "principal": _principal(metadata)})

    async def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id,
                            metadata, inputs, **kw):
        name = serialized.get("name", "?")
        is_handoff = name.startswith(HANDOFF_MARKERS) or "__handoff_destination" in (serialized.get("metadata") or {})
        await self.emit({"type": "delegation" if is_handoff else "tool_call",
                         "run_id": str(run_id), "parent_run_id": str(parent_run_id),
                         "from_agent": self.runs.get(str(parent_run_id)),
                         "to_agent": name.removeprefix("transfer_to_") if is_handoff else None,
                         "tool": name, "args": inputs or {}, "ts": _now()})

    async def on_tool_end(self, output, *, run_id, **kw):
        await self.emit({"type": "tool_result", "run_id": str(run_id),
                         "ok": True, "result_preview": str(output)[:500]})

    async def on_tool_error(self, error, *, run_id, **kw):
        await self.emit({"type": "tool_result", "run_id": str(run_id),
                         "ok": False, "error": str(error)})

# Attach without touching framework or app source — invocation wrapper only:
handler = DelegationBenchHandler(emit=sink, agents={"supervisor", "researcher", "writer"})
result = await graph.ainvoke(
    inputs,
    config={"callbacks": [handler],
            "configurable": {"thread_id": tid},
            "metadata": {"user_id": principal_id}},   # principal carrier — propagates to all events
)
```

If the harness uses `create_agent`, optionally add a `wrap_tool_call` middleware for richer
`ToolCallRequest` payloads (typed args, state, runtime) — same event schema.

### 8. Risks

- **No principal identity primitive** — user context must be harness-injected via
  `config["metadata"]` (propagates) or mapped from `thread_id`. If the target app doesn't
  cooperate, the originating user is unrecoverable from events alone.
- **Handoff detection is convention-based** — `transfer_to_*` naming covers
  langgraph-supervisor and docs examples; custom handoff tools need registration or a
  metadata probe (`__handoff_destination`). Custom `StateGraph` delegations may need
  per-scenario rules.
- **`langgraph-supervisor` is 0.0.x** with a slow release cadence — treat its metadata keys
  as de-facto, not contractual.
- **Middleware API is young** (LangChain 1.0, Oct 2025) — higher churn risk; secondary
  mechanism only.
- **Known event gaps**: `tool_call_id` missing from `on_tool_start`
  (langchain-ai/langchain#34168); tool errors inside `ToolNode` historically emitted
  without matching `on_tool_end` in some paths — handle dangling runs in the tree builder.
- **Fast release cadence** — pin versions, run adapter tests on upgrade.

## Sources (all accessed 2026-07-23)

- [LangChain docs — Multi-agent overview](https://docs.langchain.com/oss/python/langchain/multi-agent)
- [LangChain docs — Handoffs pattern](https://docs.langchain.com/oss/python/langchain/multi-agent/handoffs)
- [LangChain docs — Custom middleware](https://docs.langchain.com/oss/python/langchain/middleware/custom)
- [langchain-core reference — `Runnable.astream_events`](https://reference.langchain.com/python/langchain-core/runnables/base/Runnable/astream_events)
- [langchain-core reference — `CallbackManagerMixin.on_tool_start`](https://reference.langchain.com/python/langchain-core/callbacks/base/CallbackManagerMixin/on_tool_start)
- [langchain-core reference — `CallbackManagerMixin.on_chain_start`](https://reference.langchain.com/python/langchain-core/callbacks/base/CallbackManagerMixin/on_chain_start)
- [langgraph-supervisor reference — supervisor module](https://reference.langchain.com/python/langgraph-supervisor/supervisor)
- [langgraph-supervisor source — `handoff.py`](https://raw.githubusercontent.com/langchain-ai/langgraph-supervisor-py/main/langgraph_supervisor/handoff.py)
- [PyPI — langgraph-supervisor](https://pypi.org/project/langgraph-supervisor/)
- PyPI JSON API for `langgraph`, `langchain`, `langchain-core` (version/release dates)
- [GitHub — langchain#34168 (tool_call_id not passed to on_tool_start)](https://github.com/langchain-ai/langchain/issues/34168)
- [GitHub — langgraph discussion #2606 (missing on_tool_error in astream_events)](https://github.com/langchain-ai/langgraph/discussions/2606)
