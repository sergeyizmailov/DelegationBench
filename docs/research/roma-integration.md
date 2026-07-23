# ROMA Integration Feasibility Audit — DelegationBench

## Executive Summary

- **Feasible without modifying ROMA source.** ROMA v2 (`roma_dspy`) exposes three non-invasive observation surfaces: the DSPy callback API (`dspy.utils.callback.BaseCallback`), the in-memory `TaskDAG` with full parent/child links and per-task execution history available post-run via `solver.last_dag`, and a contextvars-based `ExecutionContext` whose event buffers an adapter can read or extend.
- **The delegation tree is explicit and complete.** Every subtask carries `parent_id`, `depth`, and a `subgraph_id`; `TaskDAG` nests subgraphs with `parent_dag` back-references. The entire delegation chain can be reconstructed from one object after a run.
- **There is no single tool-call chokepoint function**, but all builtin and MCP tools are wrapped at registration time by the `track_tool_invocation` decorator, and every tool call fires DSPy `on_tool_start`/`on_tool_end` callbacks — both are clean hook points.
- **Trace coverage has real gaps.** Most module-level event types (`subtask_created`, `plan_complete`, `execute_complete`, `task_transition`) are defined in the enum but **never emitted**; tool-invocation records do **not** carry a `task_id`; event-driven mode emits no per-task events at all. An adapter must patch or correlate to close these gaps.
- **Licensing is ambiguous and is the top risk.** No `LICENSE` file exists at the audited commit, GitHub reports `licenseInfo: null`, and `pyproject.toml` has no license field — yet the README claims Apache 2.0 and links to a missing file. Treat as all-rights-reserved: adapter must be import-only / clean-room.
- **Maintenance is slowing.** Last commit 2026-02-17 (~5 months before research date), 15 open vs 38 closed issues, and the two governance-related issues (#90, #92) sit unanswered — both are third-party product pitches, not maintainer initiatives.

## Scope

- **Research date:** 2026-07-23 (UTC)
- **Repository:** https://github.com/sentient-agi/ROMA (verified canonical; described as "Recursive-Open-Meta-Agent v0.1 (Beta)"). The default branch now hosts **ROMA v2 ("ROMA-DSPy")**, a full rewrite on DSPy; the original v1 (Flask-based) code is not on the default branch.
- **Audited commit:** `a6e3bb4f9e0694375fa627fa4b8bf8cae50592a6` (2026-02-17, "Update paper link and citation in README.md"), shallow clone at `/tmp/roma-audit`
- **Package version:** `0.1.0` (`pyproject.toml:3`, `src/roma_dspy/__init__.py`); latest GitHub release tag `v0.2.0-beta` (2025-10-22)
- **Method:** source reading of `src/roma_dspy/` (core engine, modules, tools, observability, context), plus GitHub API/`gh` for repo metadata and issues.

## Findings

### 1. How subtasks are created (recursive decomposition)

The decomposition pipeline is a state machine in `RecursiveSolver` (`src/roma_dspy/core/engine/solve.py:38`):

- `_async_execute_state_machine` (`solve.py:944`) routes each task: **Atomizer** decides PLAN vs EXECUTE (`runtime.atomize_async`, `solve.py:956`), **Planner** decomposes (`runtime.plan_async`, `solve.py:963`), then either **Executor** runs it (`solve.py:982`) or the subgraph is recursed (`runtime.process_subgraph_async`, `solve.py:1001`).
- `Atomizer` (`src/roma_dspy/core/modules/atomizer.py:13`) and `Planner` (`src/roma_dspy/core/modules/planner.py:13`) are thin DSPy modules over `AtomizerSignature` / `PlannerSignature`.
- The actual subtask objects are born in `ModuleRuntime._create_subtask_graph` (`src/roma_dspy/core/engine/runtime.py:917-998`): each planner-produced subtask becomes a `TaskNode` at `runtime.py:924-931`.
- Recursion: `process_subgraph_async` (`runtime.py:732`) → `solve_subgraph_async` (`runtime.py:744`) → `_execute_tasks_parallel` (`runtime.py:1037`) which calls `solve_fn` — bound to `RecursiveSolver._async_solve_internal` passed down at `solve.py:999-1003`. Depth is capped by `max_depth`; `task.should_force_execute()` forces direct execution at the limit (`solve.py:949`).
- A second, event-driven execution mode exists: `EventLoopController` (`src/roma_dspy/core/engine/event_loop.py`) drives the same per-task state machine through an async priority queue (`_handle_ready`, `event_loop.py:262-341`), entered via `RecursiveSolver.event_solve` / `async_event_solve` (`solve.py:682`, `824`).

### 2. Parent task reference / task tree

Explicit and first-class:

- `TaskNode` (`src/roma_dspy/core/signatures/base_models/task_node.py:16`) is an immutable (frozen, `extra="forbid"`, `task_node.py:33-38`) Pydantic model with `parent_id` (`:80`), `children` frozenset (`:116`), `subgraph_id` (`:132`), `depth`/`max_depth` (`:87-88`), and `execution_id` (`:82`).
- `TaskDAG` (`src/roma_dspy/core/engine/dag.py:16`) is a networkx-backed graph that nests: `create_subgraph` (`dag.py:301-378`) builds a child `TaskDAG` with `parent_dag=self` (`dag.py:319-321`), names it `f"{dag_id}_sub_{parent_task_id}"` (`dag.py:318`), stamps each subtask's `parent_id` (`dag.py:330`), and writes the `subgraph_id` back onto the parent task (`dag.py:375`).
- Navigation helpers exist: `get_all_tasks(include_subgraphs=True)` (`dag.py:392`), `get_task_children` (`dag.py:425`), `find_node` across nested DAGs (`dag.py:669`), `export_to_dict` (`dag.py:496`).
- After any run, the full tree is reachable at `solver.last_dag` (thread-local, `solve.py:170-178`).

### 3. Executors and the executor boundary

- `Executor` (`src/roma_dspy/core/modules/executor.py:22`) is a DSPy module (inherits `BaseModule`, `src/roma_dspy/core/modules/base_module.py:35`). Prediction strategy is configurable (`PredictionStrategy.CHAIN_OF_THOUGHT` default; ReAct/CodeAct supported, see `base_module.py:156-181`). Models are `dspy.LM` instances — i.e., any LiteLLM-reachable API or local model.
- The executor boundary is `ModuleRuntime.execute_async` (`runtime.py:559`), funneled through `_execute_agent_with_tracing` (`runtime.py:400`), which resolves the agent from `AgentRegistry` by `(AgentType, task.task_type)` (`runtime.py:413`) — so "executors" are pluggable per task type (THINK/RESEARCH/WRITE/CODE/etc.) via config (`AgentFactory`, `core/factory/agent_factory.py`). Other agent-like behaviors (verifier, aggregator) go through the same boundary.
- Tools may themselves be remote: `MCPToolkit` (`src/roma_dspy/tools/mcp/toolkit.py`) wraps external MCP servers, so part of the executor boundary extends to out-of-process tool servers.
- Each agent execution is wrapped in an observability span (`runtime.py:458-459`) and its inputs/outputs/token usage recorded into the task's `execution_history` (`runtime.py:894-915`).

### 4. Tool invocation points / chokepoint

No single chokepoint function exists; tools are plain callables handed to DSPy (ReAct) which invokes them inside its loop. But there are three reliable interception layers:

1. **Registration-time wrapping:** every builtin toolkit method is wrapped by `track_tool_invocation` in `BaseToolkit._register_all_tools` (`src/roma_dspy/tools/base/base.py:212-216`; decorator at `src/roma_dspy/tools/metrics/decorators.py:298`). MCP tools get the same wrapper (`tools/mcp/toolkit.py:575`, `:651`). This decorator is a monkey-patch-friendly chokepoint.
2. **DSPy callback API:** DSPy ≥3 fires `on_tool_start`/`on_tool_end` on every tool call. ROMA's own `ROMAToolSpanCallback` (`src/roma_dspy/core/observability/tool_span_callback.py:40`) is proof this hook sees all tool traffic; it's registered via `dspy.settings.configure(callbacks=[...])` (`src/roma_dspy/core/observability/mlflow_manager.py:151-158`). ROMA deliberately preserves pre-existing callbacks when invoking modules (`runtime.py:449-455`), so an adapter's callback coexists.
3. **ToolkitManager singleton** (`src/roma_dspy/tools/base/manager.py:24`, `get_instance` at `:62`, `get_tools_for_execution` at `:451`): central registry through which all per-execution tool resolution flows; also supports `register_external_toolkit` (`manager.py:141`) for adapter-supplied tools.

### 5. Existing traces/logs and formats

- **Task tree + per-task history:** `TaskNode.execution_history: Dict[str, ModuleResult]` (`task_node.py:121`) stores each module run's input, output, duration, `token_metrics`, and raw LM `messages` (`runtime.py:894-915`); `NodeMetrics` tracks counts (`task_node.py:127`). Token rollups: `get_total_input_tokens` / `get_total_output_tokens` (`solve.py:180-228`). Format: in-memory Pydantic; serializable via `TaskDAG.export_to_dict`.
- **Execution events:** `ExecutionEventType` enum (`src/roma_dspy/types/execution_event_type.py:6-28`) defines 10 event types, **but only `execution_start`, `execution_complete`, `execution_failed` are ever emitted** (`solve.py:590`, `:632`, `:652`). `SUBTASK_CREATED`, `TASK_TRANSITION`, and the module-completion events have zero emit sites (verified by repo-wide grep). Events buffer in `ExecutionContext.execution_events` (`src/roma_dspy/core/context/execution_context.py:231-273`) and persist to Postgres via `persist_metrics` (`execution_context.py:275-358`). Also note: per-task events only fire in recursive mode; the event-driven controller calls runtime methods directly and emits none.
- **Tool invocations:** recorded as `ToolInvocationEvent` (execution_id, toolkit, tool name, duration, I/O sizes, success/error) into `ctx.tool_invocations` by `ROMAToolSpanCallback.on_tool_end` (`tool_span_callback.py:243-319`) — **only when MLflow is enabled**, and **without any task_id** (fields at `tool_span_callback.py:294-307`), so tool→task attribution is not provided out of the box.
- **Checkpoints:** full DAG snapshots serialized to JSON files on disk (`src/roma_dspy/resilience/checkpoint_manager.py:52-123`, `*.json` in a configurable `storage_path`), optionally mirrored to Postgres. Triggers include execution start/complete, after-planning, before-aggregation.
- **MLflow (optional):** `mlflow.dspy.autolog` plus ROMA spans with `roma.*` attributes (`core/observability/span_manager.py:35`, `mlflow_manager.py`); LM traces also persistable to Postgres (`runtime.py:330`, `runtime.py:467-472`).
- **Logs:** loguru throughout; TUI consumes traces. Config-gated via `config.observability` (event_traces / mlflow) in `src/roma_dspy/config/schemas/`.

### 6. Observing delegation + tool calls without modifying ROMA

Yes, with a layered strategy:

- **Post-hoc tree reconstruction (zero patching):** run via the public API (`solve`, `async_solve`, `event_solve`, exported in `src/roma_dspy/__init__.py:22-60`), then walk `solver.last_dag` — every node's `parent_id`, `depth`, `task_type`, status, result, and full `execution_history` (including LM messages and token metrics) is available. This alone covers delegation-chain reconstruction.
- **Live tool-call observation (zero patching):** register a custom `dspy.utils.callback.BaseCallback` in `dspy.settings.callbacks` before the run — ROMA preserves external callbacks (`runtime.py:449-455`). `on_tool_start`/`on_tool_end` deliver tool name, inputs, outputs, exceptions. `on_module_start`/`on_module_end` let the adapter maintain a task stack for tool→task attribution (compensating for the missing `task_id` in ROMA's own records).
- **ExecutionContext (contextvars):** `ExecutionContext.get()` (`execution_context.py:109`) is readable anywhere in the run; an adapter can append to or drain `execution_events` / `tool_invocations`, and can stash run-scoped data on the context object itself.
- **Monkey-patch-friendly structure:** plain Python classes, no `__slots__` seal on the relevant methods; natural patch points are `ModuleRuntime._create_subtask_graph` (intercept each subtask at birth, `runtime.py:917`), `RecursiveSolver._emit_execution_event` (`solve.py:363`), and `track_tool_invocation` (`metrics/decorators.py:298`). The solver's `__deepcopy__`/`__getstate__` machinery (`solve.py:230-331`, `modules/recursive_solver.py:146-186`) means patches must be applied at class level, not instance level, to survive solver spawning.
- **Not present:** no event bus, no plugin system, no public hook registry. Everything above is convention-based but stable within this commit.

### 7. Metadata propagation through the task tree

- `TaskNode` is frozen with `extra="forbid"` (`task_node.py:33-38`) — **no new fields without subclassing/patching**. It does have a `metadata: Optional[Dict[str, Any]]` field (`task_node.py:108`).
- **But metadata is not propagated:** `_create_subtask_graph` copies only `goal`, `task_type`, `parent_id`, `depth`, `max_depth`, `execution_id` into children (`runtime.py:924-931`). Parent→child context flows instead as **prompt-level XML**: `RecursionContext` (depth limits, `core/context/models.py:205`), `PlannerSpecificContext` with `ParentResult`/`SiblingResult` (`models.py:467-561`), built by `ContextManager` (`core/context/manager.py`, invoked at `runtime.py:429-443`). This is LLM-facing context, not a machine-checkable channel.
- **Where an authorization envelope could live (no source change):**
  1. **Adapter side-channel** keyed by `task_id`/`parent_id`, populated by patching `_create_subtask_graph` or by consuming the DAG live — cleanest, fully external.
  2. **`ExecutionContext`** (contextvar): propagates automatically through async children; suitable for a root envelope, but it is execution-scoped, not per-task, so per-hop attenuation needs the side-channel anyway.
  3. **Monkey-patched `_create_subtask_graph`** that additionally copies `task.metadata` into each child — a 5-line runtime patch, no file modification; fragile across versions.
  4. Stuffing the envelope into the root goal string — visible in prompts/traces; not recommended.
- Net: per-task envelope propagation is achievable but requires the adapter to own it; ROMA gives you the tree keys (`task_id`, `parent_id`, `depth`) to hang it on.

### 8. Test hooks / programmatic usage examples

- Public API: `from roma_dspy import solve, async_solve, event_solve, RecursiveSolver, TaskDAG, TaskNode` (`src/roma_dspy/__init__.py`); convenience functions with config overrides at `solve.py:1284-1392`.
- README quickstart: `python -c "from roma_dspy.core.engine.solve import solve; print(solve('What is 2+2?'))"` (`README.md:155`); SDK example at `README.md:247`.
- `tests/test_sdk_usage.py` — import surface and solver construction patterns; `tests/test_engine.py`, `tests/test_parallel.py` (concurrency), `tests/integration/`, `tests/test_minimal_e2e_real_install.py`.
- `notebooks/example.ipynb`, `notebooks/trial_run.ipynb`, `notebooks/prompt_optimization.ipynb`; `benchmarks/harbor/` for benchmark harness patterns.
- CLI entry point `roma-dspy = roma_dspy.cli:app` (`pyproject.toml:126`); config via YAML profiles + `ROMAConfig` (`src/roma_dspy/config/`).
- Dependency floor: `dspy>=3.0.3`, `pydantic>=2.11.9`, Python ≥3.12 (`pyproject.toml:12-32`). Note `dspy` has **no upper bound** — callback API drift is a compatibility risk.

### 9. Maintenance status (as of 2026-07-23)

- Last push: **2026-02-16/17** (audited commit is HEAD) — ~5 months stale.
- ~124 commits on the default branch; cadence is bursty: heavy "benchmark" commits Nov–Dec 2025, resilience/logging work Jan 2026, only a README touch in Feb 2026.
- Stars: **5,100**; forks: **772**; repo created 2025-05-12.
- Issues: **15 open / 38 closed**. Latest release `v0.2.0-beta` (2025-10-22).
- Governance-relevant issues #90 and #92 (below) are unanswered, suggesting limited maintainer bandwidth for security/audit-trail features.

### 10. Licensing

- **No `LICENSE` file** exists in the repo root at the audited commit (verified by directory listing of the clone).
- GitHub API reports **`licenseInfo: null`**.
- `pyproject.toml` has **no `license` field and no license classifier**.
- `README.md:928-930` claims "licensed under the Apache 2.0 License - see the LICENSE file" — a dangling reference to a file that does not exist. Likely a leftover from ROMA v1.
- **Issue #90** — "Feature: AgentID for hierarchical meta-agent identity" (https://github.com/sentient-agi/ROMA/issues/90): OPEN, created 2026-03-22 by `haroldmalikfrimpong-ops`, 0 comments, no maintainer response. Proposes ECDSA P-256 per-agent certificates and trust scores for parent-child agent identity chains; reads as a third-party product pitch (links getagentid.dev).
- **Issue #92** — "Integration: Governance layer for meta-agent orchestration" (https://github.com/sentient-agi/ROMA/issues/92): OPEN, created 2026-04-06 by `jagmarques`, 0 comments, no maintainer response. Proposes `asqav` signed receipts per delegation step for cryptographic chain of custody; also a product pitch.
- Signal: community demand exists for exactly what DelegationBench measures, but upstream has not engaged — do not expect these to land.

### 11. Version audited

- Commit: `a6e3bb4f9e0694375fa627fa4b8bf8cae50592a6` (HEAD of default branch, 2026-02-17).
- Package: `roma-dspy` v0.1.0; release line: ROMA v2 "DSPy" (`v0.2.0-beta` tag). ROMA v1 (Flask, Docker-compose microservices) was not audited.

## Adapter Design Sketch

**Constraint:** import-only integration; no ROMA source modification, no code copying (license unclear).

Events the adapter must capture, and where to hook them:

| Event | Hook | Mechanism |
|---|---|---|
| Run start / root task | `RecursiveSolver.solve/async_solve/event_solve` call site | Adapter wraps the public entry call; captures root goal, config, `execution_id` |
| Subtask created (delegation edge) | `ModuleRuntime._create_subtask_graph` (`runtime.py:917`) | Class-level monkey-patch: emit `(parent_id, task_id, depth, goal, task_type)` per new `TaskNode`; or derive post-hoc from `last_dag` |
| Task lifecycle (atomize/plan/execute/aggregate, status, result) | DSPy `on_module_start`/`on_module_end` + DAG walk | Custom `BaseCallback` registered in `dspy.settings.callbacks`; module name ↔ agent type; correlate with DAG nodes |
| Tool call (name, args, result, error, timing) | DSPy `on_tool_start`/`on_tool_end` | Same callback; attribute to task via a module-call stack maintained in the callback (ROMA's own `ToolInvocationEvent` lacks `task_id`) |
| Token usage / LM calls | DSPy `on_lm_start`/`on_lm_end`, or post-hoc `execution_history[].token_metrics` | Callback or tree walk |
| Run end / final tree | After `solve()` returns | Walk `solver.last_dag` (`get_all_tasks(include_subgraphs=True)`); full tree, statuses, results, histories |
| Failure events | `on_tool_end(exception=...)`, module callback exceptions, `TaskNode.error` | Callback + tree walk |

**Authorization envelope:** adapter-owned side-channel map `task_id → envelope`, seeded at root call, attenuated on each `subtask_created` event; `parent_id`/`depth` from the DAG provide the chain. Optionally mirror the root envelope onto `ExecutionContext` for in-run access. No ROMA changes required.

**Recommended adapter shape:** a single `DelegationBenchCallback(dspy.utils.callback.BaseCallback)` + a thin wrapper around `RecursiveSolver` construction (to pin config, register the callback, and expose `last_dag`), plus an optional class-level patch of `_create_subtask_graph` for real-time delegation edges (without it, edges are still fully recoverable post-hoc).

## Licensing Situation

The audited commit has **no LICENSE file, no license metadata (`licenseInfo: null`), and no license field in packaging**, while the README asserts Apache 2.0 against a missing file. Until upstream fixes this, the safe legal posture is *all rights reserved*: the DelegationBench adapter must (a) import ROMA as an external dependency only, (b) contain no copied or derived ROMA code, (c) interact exclusively through public APIs, callbacks, and runtime monkey-patching. Vendoring, forking, or copying signatures/prompts out of ROMA is not safe. Filing/👍-ing an upstream issue asking to restore the LICENSE file is worthwhile; given current maintainer responsiveness (#90/#92 unanswered), do not block on it.

## Risks & Open Questions

1. **License ambiguity (top risk).** No enforceable grant of rights; redistribution of anything derived from ROMA is unsafe. Adapter must stay clean-room/import-only. A future LICENSE change could also alter terms mid-project.
2. **Trace gaps require compensation.** Module-level events are defined-but-never-emitted; tool records lack `task_id`; event-driven mode emits no per-task events. Attribution depends on the adapter's own callback-stack correlation — workable but must be validated against both execution modes (recursive and event-driven).
3. **Maintenance slowdown / API drift.** HEAD is ~5 months old; `dspy>=3.0.3` is unpinned above, so the DSPy callback API the adapter depends on can shift under it. Pin and test a known-good `dspy` version alongside the audited ROMA commit.
4. **Patch fragility.** Monkey-patching `_create_subtask_graph` / `track_tool_invocation` targets private APIs that may change without notice; the solver's deepcopy/pickle spawning (`recursive_solver.py:227-238`) means instance-level patches are silently dropped — patch at class level only.
5. **Concurrency semantics.** `max_concurrency` > 1 and asyncio.gather over sibling subtasks (`runtime.py:1037-1047`) mean delegation events interleave; the adapter must key strictly on `task_id`, never on call order. `ExecutionContext` is execution-scoped (not task-scoped), so contextvar-based attribution across parallel tasks needs care.
6. **Open questions:** Does DSPy's callback API guarantee `on_tool_end` pairing under ReAct exceptions (ROMA's own callback has a stale-call sweeper, `tool_span_callback.py:79-129`, implying it does not)? Do MCP tool calls crossing process boundaries need separate capture? Is Postgres persistence (`save_event_trace` etc.) worth using as a truth source vs. the in-memory DAG?

## Sources

- https://github.com/sentient-agi/ROMA — repository, cloned and read at commit `a6e3bb4` (accessed 2026-07-23)
- https://github.com/sentient-agi/ROMA/releases/tag/v0.2.0-beta — latest release metadata (accessed 2026-07-23)
- https://github.com/sentient-agi/ROMA/issues/90 — "Feature: AgentID for hierarchical meta-agent identity" (accessed 2026-07-23)
- https://github.com/sentient-agi/ROMA/issues/92 — "Integration: Governance layer for meta-agent orchestration" (accessed 2026-07-23)
- GitHub REST/GraphQL API via `gh` — stars, forks, issue counts, license info, commit history (accessed 2026-07-23)
- Source files cited inline under `src/roma_dspy/` (core/engine/solve.py, runtime.py, dag.py, event_loop.py; core/modules/*; core/signatures/base_models/task_node.py; core/context/*; core/observability/*; tools/base/*; tools/metrics/decorators.py; resilience/checkpoint_manager.py; pyproject.toml; README.md)
