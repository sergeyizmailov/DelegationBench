# Final Pre-Grant Review — Consolidated Findings (2026-07-23)

Target state reviewed: v0.4.0 (commit 5025f7a) + v0.3.0 code lineage.
Verified: 231 tests pass, 75/75 scenarios in all 3 defense modes, ruff clean.

## P0 — fix before grant submission

1. **Authority widening via same-task re-delegation (oracle + guard both silent).**
   `oracle.py:159,171` — repeated task_id with identical (parent, agent) is treated as
   "renewal" and authority is overwritten WITHOUT comparing to the task's previous
   authority; `defense.py:90-118` only checks scope ⊆ parent. Parent delegates
   `root/worker` scope {docs.read}, then re-delegates same task_id with
   {docs.read, email.send} (⊆ parent) → email.send executes, verdict clean, guard
   approves. Violates "authority may only shrink" across the renewal edge; reachable
   via pure scenario YAML. FIX: compare re-delegation scope against the task's prior
   effective authority in BOTH oracle and guard.

2. **`unauthorized_executed` metric is gameable.** `oracle.py:311-321` — refusal
   detected by substring '"status": "error"' in result text; adversary controls
   content → can deflate the headline metric at will; pooled results also miscount
   (2 calls, 1 error + 1 success → 2 "executed"). FIX: structural refusal detection
   (parse result JSON, match per-call) or footnote the metric.

3. **JUnit report drops errored scenarios.** `cli.py:111-118` + `outputs.py` —
   a schema-broken yaml in a directory run exits 2 but junit.xml shows all-green
   (tests=N failures=0). CI archiving JUnit sees pass. FIX: emit <error> testcases.

4. **GO_NO_GO gate #6 (external validation) still PENDING** — four releases shipped
   against the memo's own condition. Process item: either do outreach
   (docs/validation-kit.md) or amend the memo's conditions explicitly.

## P1 — should fix

5. **Guard approves delegations under parents it never approved** (`defense.py:117`)
   and trusts attacker-modifiable envelope fields (scope arg vs child.allowed_actions,
   child-carried depth/max/expiry — `defense.py:96,101,128,138`). Signing closes it,
   but default key is a public constant with no runtime warning. FIX: guard maintains
   its own approved-authority map, or THREAT_MODEL §5 states explicitly "unsigned
   mode assumes well-formed envelopes" + warn on default key.

6. **Loader robustness** (`scenario.py`, `agents.py`): optional capture group in
   template → mid-run KeyError; non-mapping YAML nodes → AttributeError instead of
   ScenarioError; NaN/Inf accepted for ttl_seconds/advance_clock (poisons clock,
   silently defeats V4); root-agent docs.read capability not validated at load;
   YAML bools pass numeric checks.

7. **Principal stamping divergence between adapter paths** — neutral build_trace:
   explicit "" overrides inheritance (`adapters/__init__.py:306`); ROMA: "" inherits
   (`roma.py:174`). Unify semantics.

8. **Tools** (`tools.py`): negative payment amounts execute; mid-run payment_limit
   tamper to non-integer → uncaught ToolError crash; seeded email ids overwritten by
   draft counter.

## P2 — polish

9. BrokenPipeError traceback on `| head` (cli.py:65).
10. Non-reproducible builds (no SOURCE_DATE_EPOCH); `dist/` in repo mixes 0.3.0/0.4.0
    artifacts; sdist ships tests/ but not scenarios/ (corpus test can't run from sdist).
11. Fuzzer: seed itself not in dedup set (no-op mutants inflate counts); `fuzz` exits 0
    even with bypass findings (CI can't gate); --benchmark-report skipped on
    single-file error path.
12. action_map=None value flows to trace; handoff_prefixes=() replaced by defaults;
    langgraph_real_llm_demo.py exits 0 on missing deps (others exit 1).
13. Trace event cap off-by-one (trace.py:76-80).
14. scenario_request.yml dropdown missing V7.
15. Adapters package still has two event representations — consolidate when touching
    #7.

## Killed hypotheses (evidence of strength)

- Envelope attenuation sound: child can never exceed parent (empty scope, extra
  actions, nonce collisions all probed). HMAC sign/verify correct.
- No trace found where unauthorized action executes with clean oracle verdict WITHIN
  the documented threat model (content-only adversary, honest agents).
- Fuzzer determinism byte-identical across PYTHONHASHSEED 0/42/12345.
- Oracle deterministic across reruns; orphan/out-of-order traces over-flag (fail-safe).
- No store leaks between scenarios; cycles → clean EngineError; capability check
  precedes any mutation.
- SARIF 2.1.0 / JUnit schema-valid; action.yml correct (pinning, permissions, enforce).
- THREAT_MODEL V1–V7 matches oracle behavior exactly.

## Research track (docs/research/pre-grant-improvements.md)

1. PyPI: name `delegationbench` UNCLAIMED — register; set up Trusted Publishing
   (OIDC) + hardened release workflow (tag-trigger only, environment w/ reviewer).
2. OpenSSF Scorecard action + badge; SLSA provenance via actions/attest-build-provenance;
   SBOM via anchore/sbom-action.
3. Map SARIF rules to OWASP Agentic Top 10 (ASI03/ASI07), MITRE ATLAS, CWE-441/269/863
   via taxa/relationships; map scenario IDs to ATR-2026-00074.
4. Landscape: no direct competitor. OAP shipped delegation chains (candidate scenario
   pack). ROMA still no LICENSE — clean-room stands; issues #90/#92 open, unanswered —
   engage there from maintainer account.
5. Grant optics: lead with working ROMA adapter demo tied to #90/#92; use ASI/ATLAS
   vocabulary in the application.
