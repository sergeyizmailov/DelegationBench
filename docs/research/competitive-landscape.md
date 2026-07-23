# Competitive Landscape — DelegationBench Feasibility Audit

Research date: 2026-07-23. Per-project details: `docs/research/competitive/*.md`.

## Executive Summary

- **No direct equivalent found.** Across 10 candidates, overlap verdicts are NONE or
  PARTIAL only. Nothing combines all of: multi-agent delegation chains, differential
  per-agent privileges, originating-user tracking, chain-wide deterministic authority
  oracle, attack generation, exploit minimization, and regression-test emission.
- **Closest neighbors:** Open Agent Passport (delegation chains exist but spec-only,
  enforcement not benchmarking), Agent Threat Rules (detects cross-agent privesc in
  traffic but content-matching, no authority model), Agent-Fence paper (delegation
  attack classes + trace predicates, no runnable artifact, human adjudication).
- **Several "competitors" are better cast as targets/baselines:** ScopeGate and Open
  Agent Passport are authorization systems DelegationBench should *test*; AgentDojo
  validates the deterministic-oracle design in the single-agent setting.
- **Licensing note:** two closest fuzzing projects (AgentFuzz, ChainFuzzer) ship no
  license and/or no code — reuse is limited to ideas, not artifacts.

## Comparison Matrix

Legend: Y = yes, P = partial, N = no. Columns: (2) multi-agent · (3) differential
privileges · (4) origin tracking · (5) chain-wide authority check · (6) attack
generation · (7) exploit minimization · (8) regression-test emission.

| Project | 2 | 3 | 4 | 5 | 6 | 7 | 8 | License | Liveness (2026-07-23) | Overlap |
|---|---|---|---|---|---|---|---|---|---|---|
| AgentFuzz (USENIX Sec'25) | N | N | N | N | Y | N | N | none | 94★, stale since 2026-04, academic artifact | PARTIAL |
| ChainFuzzer (arXiv 2603.12614) | N | N | P | N | Y | P | N | none (no code) | preprint only, ~4 citations | PARTIAL |
| AgentDojo (ETH, NeurIPS'24) | N | N | N | N | P | N | N | MIT | 678★, last commit 2026-06 | PARTIAL |
| Agent Security Bench (ICLR'25) | N | N | N | N | P | N | N | MIT | 273★, last commit 2026-04 | PARTIAL |
| AgentFence (repo / arXiv 2602.07652) | N/P | N/P | N/P | N/P | P | N | N | MIT (repo) / none (paper) | repo dormant ~16 months; paper no code | NONE / PARTIAL |
| ScopeGate Runtime | N | P | N | N | N | N | P | Apache-2.0 | 0★, 2 commits, paper artifact | NONE (defense, not testbed) |
| Agent Threat Rules | P | P | N | N | N | N | N | MIT | 347★, pushed today, very active | PARTIAL |
| OASB (Open Agent Security Benchmark) | P | P | N | N | N | N | P | Apache-2.0 | 7★, active, tiny community | PARTIAL |
| Open Agent Passport | P | Y | Y(spec) | Y(spec) | N | N | N | mixed MIT/Apache-2.0 | active, small (25★) | PARTIAL (closest infra) |
| Confused-deputy demos (ConfusedPilot, Imprompter, arXiv 2503.12188) | N/Y | P | N | N | N/P | N | N | none / GPL-2.0 | papers only, dormant code | PARTIAL |

## Key Findings per Category

**Fuzzers (AgentFuzz, ChainFuzzer).** Both do taint-style source→sink analysis on
*single* agents. Deterministic oracles exist but judge reachability, not
authorization vs an originator's grant. No delegation, no privilege model. ChainFuzzer
has no public code at all. Their mutation machinery is conceptually reusable.

**Benchmarks (AgentDojo, ASB, OASB).** Single-agent or message-scanning. Fixed attack
corpora, no generation, no minimization, no regression emission. OASB itself admits
"no attack-chain aggregation". AgentDojo's deterministic trace-based scoring validates
our oracle philosophy; none model an originating user.

**Detection rules (Agent Threat Rules).** Only project actively shipping cross-agent
privesc *detection* (35 privesc rules), but regex/content-matching: no permission
model, no origin tracking, chain correlation spec proposed but unratified with zero
shipped rules. Very active single maintainer — potential consumer of our scenarios,
not a competitor.

**Authorization infrastructure (ScopeGate, Open Agent Passport).** These *enforce*,
they don't test. OAP is the closest conceptually: delegation-chain spec with
scope-narrowing intersection (Apr 2026 draft) — but zero implementation of chains in
the SDK, no oracle, no attacks, no benchmarks. Both are natural *targets* for
DelegationBench evaluation.

**Academic demos.** arXiv 2503.12188 (COLM'25) demonstrates multi-agent control-flow
hijack with 58–100% code-exec success — confirms the failure mode is real and
unsolved, builds no reusable test infrastructure. ConfusedPilot/Imprompter are
single-agent/RAG demonstrations.

## Gap Confirmed

The DelegationBench niche — **executable, framework-neutral tests of authority
propagation across delegation chains, judged deterministically against the
originating user's grant, with generation + minimization + regression emission** —
is unoccupied. The strongest collision risk is Open Agent Passport implementing its
delegation-chain spec; monitoring its repo is advised.

## Sources

Per-project files with full URLs and access dates: `docs/research/competitive/`.
