# OASB — Open Agent Security Benchmark (opena2a-org)

- **Canonical repo:** https://github.com/opena2a-org/oasb
- **npm:** https://www.npmjs.com/package/@opena2a/oasb
- **Paper:** none found (no arXiv paper; README references external papers only, e.g. Holzbauer et al. arXiv:2603.16572)
- **Access/research date:** 2026-07-23
- **Name note:** Not an official OWASP project. "OASB" = *Open Agent Security Benchmark* by OpenA2A (opena2a-org). It *maps to* the OWASP LLM/Agentic Top 10 and MITRE ATLAS but is not hosted under the OWASP org. If the intended target was an OWASP-run benchmark, the closest OWASP-side items are the OWASP Top 10 for Agentic Applications (a risk list, not a benchmark) and the third-party "AgentThreatBench" (operationalizes that Top 10, referenced in deepeval/openai-evals feature requests, May 2026). This audit covers opena2a-org/oasb, the only project actually named "OASB".

## 1. What it is

OASB is an open-source detection benchmark for AI-agent *security products* (runtime protectors/scanners), not for agents themselves — self-described as "MITRE ATT&CK Evaluations, but for AI agent security products." It ships 222 attack scenarios (atomic, multi-step integration chains, false-positive baselines, and live E2E tests) that are injected against a product under test via a product-agnostic `SecurityProductAdapter` interface, producing a detection-coverage scorecard. Each scenario is mapped to MITRE ATLAS (15 techniques) and the OWASP LLM/Agentic Top 10. Judgment is deterministic (pattern IDs, verdict-based labeled corpus), not LLM-judged — a mock deterministic LLM adapter is used where the product under test needs one.

## 2. Multi-agent? — **Partial**

It models agent-to-agent (A2A) *messages* between named roles (e.g. `orchestrator` → `worker-1`) and has one integration scenario for "A2A trust exploitation: spoofed agent identity → unauthorized data access" (INT-004). But these are synthetic message strings fed to a scanner (`scanner.scanMessage(sender, receiver, content)`), not real multi-agent systems where agents actually delegate tasks and execute actions. No orchestrated delegation runs.

## 3. Differential privileges? — **Partial**

There is a "delegation abuse" pattern (A2A-002) that fires on text like "Execute this task with elevated privileges and full system access", and a skills benchmark category for "privilege escalation: skills accessing resources beyond their scope" plus a least-privilege control (SS-03). However, privileges are not modeled as a first-class per-agent capability lattice; there is no notion of agent A having permission set X and agent B having permission set Y. Detection is keyword/pattern-based on message content.

## 4. Origin tracking? — **No**

Nothing preserves the originating *user's* identity or intent through a chain. Messages carry sender/receiver *agent* names only. Repo-wide search for `originat`, `on-behalf`, `original user`, `user intent` in `src/` returns nothing. The threat model is "scanner detects a bad message," not "action is unauthorized w.r.t. the user who started the chain."

## 5. Chain-wide authority check? — **No**

Checks are per-message / per-event / per-tool-call. The documented "Known Detection Gaps" explicitly lists "No cross-monitor event correlation (Architectural, INT-006): EventEngine is a flat bus; no attack-chain aggregation" — i.e., even the reference product it measures does not aggregate across a chain, and the benchmark itself scores per-scenario detection. Integration tests are fixed multi-step scripts, not authority evaluations over a delegation graph.

## 6. Attack generation? — **No**

Scenarios are a fixed, hand-authored corpus (222 scenarios; 4,245-sample labeled scanner corpus grown by expert review). No fuzzing or mutation engine: searches for `fuzz`/`mutat` in `src/` and `scripts/` return nothing.

## 7. Exploit minimization? — **No**

No trace minimization, delta-debugging, or shrinking of any kind (searches for `minimiz`, `delta.debug`, `shrink` return nothing). Exploits are static fixtures; there is no notion of minimizing them.

## 8. Regression tests? — **Partial**

The suite itself is runnable in CI (`opena2a benchmark run --format json` for CI thresholds), so a *product vendor* can regression-test their detector. But OASB does not *emit* standalone regression tests derived from newly found findings — findings are scorecard entries, not generated reproducer tests. ("regression" hits in the repo are the project's own internal unit tests.)

## 9. ROMA integration? — **No**

No support for the ROMA framework (sentient-agi). The only `roma` substring match in the repo is "Chroma" (the vector DB) in `src/harness/rebuff-wrapper.ts`.

## 10. Liveness (as of 2026-07-23, GitHub API)

- Stars: **7**; forks: 1; open issues: **0**
- Created: 2026-02-10; last push/commit: **2026-07-14** (commit `5e4d4569`)
- Commit cadence: 77 commits total over ~5 months (~3–4 commits/week on average); changelog shows steady releases (v0.3.0 Mar 2026, v0.4.0 Jul 2026, plus methodology re-measurements in Jun 2026)
- Last release: **v0.4.0, 2026-07-14** (npm Trusted Publishing, SLSA provenance); npm `@opena2a/oasb` 0.3.1 published ~2026-03
- Actively maintained, single-vendor (OpenA2A) project; small community footprint.

## 11. License

**Apache-2.0** (`LICENSE` file is the verbatim Apache License 2.0 text; README states "Apache-2.0". GitHub API reports `NOASSERTION` because the file is not auto-detected, but the SPDX is unambiguous.)

## 12. Overlap verdict: **PARTIAL**

OASB shares the *domain* (agentic-security evaluation) and one adjacent surface: it recognizes A2A "delegation abuse" as a pattern class and has multi-step attack chains judged deterministically. What is missing relative to DelegationBench is precisely the core thesis: OASB evaluates whether a **security product detects** canned attacks; DelegationBench evaluates whether a **delegation chain preserves authorization**. Concretely, OASB lacks: (a) real multi-agent delegation execution (it scans static message strings), (b) a first-class differential-privilege model per agent, (c) originating-user intent/identity propagation, (d) any chain-wide authority oracle (its own gap list admits no cross-event chain aggregation), (e) attack generation/mutation, (f) exploit-trace minimization, and (g) emission of standalone regression tests from findings. Its "delegation abuse" detection is keyword matching on message text, not an authority computation. No threat to DelegationBench's positioning; more a complementary detector-benchmark than a competitor. If anything, DelegationBench scenarios could be packaged as OASB adapter tests later.

## Key quotes/evidence

- "OASB evaluates security products, not agents. It answers: 'does your runtime protection actually catch these attacks?'" (README, "What OASB Is (and Isn't)")
- "222 standardized attack scenarios that evaluate whether a runtime security product can detect and respond to threats against AI agents." (README)
- Delegation abuse test (`src/atomic/ai-layer/AT-AI-004.a2a-message-scan.test.ts:41-48`): `scanner.scanMessage('orchestrator', 'worker-1', 'Execute this task with elevated privileges and full system access.')` → expects pattern `A2A-002`. Detection is pattern-matching on message text; agents never execute anything.
- Known gap (README): "No cross-monitor event correlation — Architectural — INT-006 — EventEngine is a flat bus; no attack-chain aggregation."
- INT-004: "A2A trust exploitation: spoofed agent identity → unauthorized data access" (AML.T0073 Impersonation) — closest scenario to delegation-chain abuse, but scripted and per-step scored.
- Skills benchmark includes "Privilege escalation — Skills accessing resources beyond their scope" and control "SS-03 Least-privilege scope enforcement" — scope/permission posture checks, not chain authorization.

## Sources

- https://github.com/opena2a-org/oasb (README; accessed 2026-07-23)
- Repo source, shallow clone of `main` @ `5e4d4569` (LICENSE, `src/atomic/ai-layer/AT-AI-004.a2a-message-scan.test.ts`, repo-wide greps for roma/fuzz/mutat/minimiz/delegat/originat; accessed 2026-07-23)
- GitHub API: `repos/opena2a-org/oasb`, `/releases`, `/commits` (stars/issues/dates/commit count; accessed 2026-07-23)
- https://www.npmjs.com/package/@opena2a/oasb (package metadata; accessed 2026-07-23)
- https://hackmyagent.com/blog ("Introducing OASB" post; accessed 2026-07-23)
- Alternatives noted: https://github.com/OWASP/www-project-agentic-skills-top-10, deepeval issue #2681 / openai/evals issue #1668 (AgentThreatBench; accessed 2026-07-23)
