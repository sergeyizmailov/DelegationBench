# GO / NO-GO Decision Memo — DelegationBench Feasibility Phase

Date: 2026-07-23
Verdict: **GO** — with two tracked external dependencies (below).

## Gate Review

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | ≥3 reproducible cross-agent attacks | **MET** | `experiments/minimal-escalation/`: injection/confused-deputy (V1+V2), depth violation (V3), expired delegation (V4). All flagged, exit code 0. |
| 2 | Violation detected by plain code, no LLM judge | **MET** | Oracle is set arithmetic over the trace (`oracle()` in `experiment.py`). No model in the loop. |
| 3 | ≥1 paired benign scenario without false blocking | **MET** | Approved-payment twin uses the identical delegation chain and tools; verdict `NO VIOLATION`. The oracle distinguishes intent (grant), not tool names. |
| 4 | ROMA or LangGraph exposes required traces | **MET** | ROMA: feasible without source modification — explicit task tree (`TaskNode.parent_id/depth`), DSPy tool callbacks, external callbacks preserved (`docs/research/roma-integration.md`). LangGraph: viable via `AsyncCallbackHandler`, `run_id`/`parent_run_id` reconstructs the delegation tree (`docs/research/langgraph-integration.md`). |
| 5 | No mature direct equivalent | **MET** | 10 candidates audited; best overlap is PARTIAL (`docs/research/competitive-landscape.md`). Nothing combines delegation chains + differential privileges + origin tracking + deterministic chain oracle + generation + minimization + regression emission. |
| 6 | ≥1 external developer confirms practical usefulness | **PENDING** | Outreach materials ready (`docs/validation-kit.md`). This is a human action and the only unmet gate. |
| 7 | One-command CI run is possible | **MET** | `python3 experiments/minimal-escalation/experiment.py` exits 0/1; trivially wrappable in any CI step. |

## Rationale

The failure mode is real and mechanically reproducible; the judgment problem —
the part that could have killed the project — is solved by construction (grant
intersection over an explicit trace, not model opinion). The competitive gap is
confirmed by source-level audit, not marketing pages. Both target frameworks
have credible adapter paths.

## Known Risks Carried into the Build Phase

1. **ROMA license ambiguity.** No LICENSE file at HEAD `a6e3bb4`, README claims
   Apache-2.0 against a missing file. Mitigation: clean-room, import-only
   adapter; license clarification request goes out with the validation outreach.
   Fallback framework (LangGraph) is already validated.
2. **ROMA trace gaps.** Module events are defined but never emitted; tool
   records lack `task_id`; adapter must correlate via its own callback stack.
   Costs adapter complexity, not feasibility.
3. **Simulated agents ≠ LLM agents.** The experiment proves the oracle, not
   attack success rates against real models. Phase 3 of the build (scenario
   suite on ≥2 models) is where probabilistic success gets measured with
   repeat trials.
4. **Competition drift.** Open Agent Passport's delegation-chain spec
   (unimplemented today) is the closest collision vector; monitor its repo.
5. **External validation pending.** Gate #6 must close before the grant
   application; if feedback reveals the report format or integration surface
   is wrong, adjust scope early — that is cheaper now than after v0.1.0.

## Conditions Attached to This GO

- Start the build (clean architecture, public Apache-2.0 repo, scenario format,
  oracle, mock tools) immediately.
- Send validation outreach (incl. ROMA license question) within the first week
  of the build; log responses in `docs/validation-kit.md`.
- Re-check gate #6 and the OAP collision vector before tagging `v0.1.0`.
- No benchmark numbers in any external communication until reproduced on real
  models (per PROJECT_PLAN §10).

## Fallbacks (unchanged from plan)

- ROMA blocked → LangGraph adapter first, document the blocker.
- Oracle proves unreliable on real-model traces → ADJUST scope.
- A direct equivalent ships during the build → PIVOT to Consent Integrity
  Testbed per PROJECT_PLAN §11.
