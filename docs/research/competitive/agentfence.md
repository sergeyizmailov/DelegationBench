# AgentFence — Competitive Audit for DelegationBench

- **Access/research date:** 2026-07-23
- **Name ambiguity:** Two distinct projects share this name. Audited below:
  - **(A) `agentfence/agentfence` (GitHub/PyPI)** — the better-known project; the most likely intended target for "agent security evaluation — find canonical repo".
  - **(B) Agent-Fence (arXiv 2602.07652, Feb 2026)** — an academic evaluation methodology paper, topically much closer to DelegationBench. No public code found.
- Also collides with unrelated uses of "agent fence" in multi-robot containment literature (ignore).

## (A) AgentFence — GitHub project (primary identification)

### 1. What it is
AgentFence is an open-source Python framework for automated adversarial security testing of LLM agents. It runs a set of predefined "probes" (prompt injection, secret leakage, system-instruction leakage, role confusion, jailbreak, harmful language, data extraction, tool access) against agent connectors (OpenAI, LangChain/LangGraph, Dialogflow) and reports pass/fail per probe.
- Canonical URL: https://github.com/agentfence/agentfence
- PyPI: https://pypi.org/project/agentfence/ (v0.1.0)
- Paper: none.

### 2. Multi-agent?
**No.** Probes target a single agent instance via a connector wrapper. No inter-agent delegation scenarios; the LangGraph connector wraps one graph, not a delegation topology.

### 3. Differential privileges?
**No.** No permission/capability model. There is a `tool_access` probe, but it tests whether one agent can be talked into misusing its tools, not a privilege lattice between principals.

### 4. Origin tracking?
**No.** No notion of an originating user, identity, or intent persisted anywhere.

### 5. Chain-wide authority check?
**No.** Checks are per-probe, judged by `LLMEvaluator` (an LLM judge) or `RegexEvaluator` on the agent's responses. No trajectory- or chain-level authority verification, and the LLM-judge design is the opposite of DelegationBench's deterministic-oracle requirement.

### 6. Attack generation?
**Partial.** Fixed library of predefined probe payloads; architecture is extensible for custom probes, but there is no fuzzing/mutation engine.

### 7. Exploit minimization?
**No.**

### 8. Regression tests?
**No.** The repo has unit tests for itself (`tests/`) but does not emit standalone regression tests from findings.

### 9. ROMA integration?
**No** mention of ROMA (sentient-agi) anywhere.

### 10. Liveness (as of 2026-07-23, via GitHub API)
- Stars: **59**; forks: 7; open issues: **1**
- Created: 2025-03-06; **last push: 2025-03-06** — the entire repo is a single-day code dump (~5 commits, all "first commit"), dormant ~16.5 months
- Releases: one, **0.1.0** (2025-03-06); PyPI mirrors this (single upload)
- Not archived, but effectively abandoned.

### 11. License
**MIT** (SPDX `MIT`; LICENSE file present, confirmed via GitHub API and PyPI metadata).

### 12. Overlap verdict
**NONE (effectively).** It is a single-agent, prompt-level probe runner with LLM-judged outcomes. It shares only the broad category "agent security testing". Missing everything that defines DelegationBench: multi-agent delegation, differential privileges, origin/intent tracking, chain-wide deterministic oracle, attack mutation, trace minimization, regression-test emission. Dead project on top of that.

---

## (B) Agent-Fence — arXiv 2602.07652 (alternative identification)

### 1. What it is
"Agent-Fence: Mapping Security Vulnerabilities Across Deep Research Agents" (Puppala, Hossain, Alam, Lee, Yoo, Ahad, Alam, Talukder; v1 submitted 2026-02-07). An architecture-centric security *evaluation methodology*: 14 trust-boundary attack classes (A1–A14) across planning, memory, retrieval, tool use, and **delegation**, with failures detected as trace-auditable "conversation breaks" (UTI, UTA, WPA, SIV, ATD predicates over an immutable execution trace). Evaluates 8 agent archetypes (Deep-Researcher, OpenDevin, AutoGPT, BabyAGI, CrewAI, LangGraph, LlamaIndex, …) with the base model fixed (Qwen2.5-32B).
- Paper: https://arxiv.org/abs/2602.07652
- Code: **none found** (Papers with Code page has no linked repo; paper's future work says "planned release of evaluation artifacts").

### Field answers (2–9), where they differ from (A)
- **2. Multi-agent? Partial.** Attack classes include Multi-Agent Role Confusion (A8) and Delegation Attacks (A9), applied to multi-agent frameworks (CrewAI, LangGraph, LlamaIndex); delegation semantics is an explicit architectural axis. But scenarios are single workload instances, not modeled privilege-escalation chains.
- **3. Differential privileges? Partial.** Tool permissions are part of the configuration metadata (allowed tool set 𝒰, budgets, scopes, argument policies π_τ); WPA covers acting "under incorrect identity/permission context". No explicit per-agent privilege ordering across a delegation chain.
- **4. Origin tracking? Partial.** The Attack Link (AL) flag and WPA predicate track whether *non-authoritative* inputs crossed trust edges and were treated as authoritative — a provenance notion, but not the originating *user's* identity/intent carried through a chain.
- **5. Chain-wide authority check? Partial.** Predicates are functions of the *whole immutable trace* 𝒯 (trajectory-level, not per-call), which is chain-wide in spirit; but there is no computation of "did the end action exceed what the origin user authorized" across a multi-hop delegation chain.
- **6. Attack generation? Partial.** Each class is instantiated by "a family of parameterized payloads" with strength varied along explicitness/persistence/scope; applied gradually over turns. Not a mutational fuzzer.
- **7. Exploit minimization? No.** No trace minimization to a shortest reproducer.
- **8. Regression tests? No.** No emission of standalone regression tests; artifacts not even released yet.
- **9. ROMA integration? No** mention found.

### 10. Liveness
Academic paper, v1 only (2026-02-07), 1 citation per Papers with Code. No repo, no releases. Cannot assess cadence.

### 11. License
**None found** (no code/artifacts released; arXiv paper only).

### 12. Overlap verdict
**PARTIAL.** This is the closest conceptual neighbor: trajectory-level, trace-evidenced authority predicates (UTI/UTA/WPA/SIV/ATD), a delegation-abuse attack class, and a semi-deterministic oracle (clear violations labeled automatically; ambiguous cases use a human rubric, κ=0.81 — not a pure LLM judge). What DelegationBench adds that Agent-Fence lacks: an explicit **privilege-differential delegation-chain model** (low-authority agent inducing a higher-authority agent), **originating-user intent/identity propagation** as the oracle's ground truth, a **fully deterministic** oracle (no human adjudication), **mutational attack generation**, **exploit-trace minimization**, **regression-test emission**, and — practically — **any released, runnable artifact**. It would not kill DelegationBench, but §3.1 (security-break predicates) and A9/A14 are the sections to differentiate against in related work.

## Key quotes/evidence
- Repo README: "AgentFence is an open-source AI security testing framework that detects vulnerabilities in AI agents… prompt injection attacks, secret leaks… robustness against manipulation." / "AgentFence is released under the MIT License."
- GitHub API (2026-07-23): `pushed_at: 2025-03-06T19:57:51Z`, `stargazers_count: 59`, `open_issues_count: 1`; single release `0.1.0`.
- Paper abstract: "14 trust-boundary attack classes spanning planning, memory, retrieval, tool use, and delegation… trace-auditable conversation breaks (unauthorized or unsafe tool use, wrong-principal actions, state/objective integrity violations, and attack-linked deviations)."
- Paper §3.1: "We implement each predicate as f(𝒯, g_i, θ) → {0,1} with thresholds fixed before evaluation."
- Paper §5: "AL, WPA, and ATD labels are assigned using a semi-automatic rubric. Clear violations… are labeled automatically; ambiguous cases are independently annotated by two reviewers and adjudicated."
- alphaxiv overview: "评估工件的计划发布" — evaluation artifacts only *planned* for release.

## Sources
- https://github.com/agentfence/agentfence (accessed 2026-07-23)
- https://api.github.com/repos/agentfence/agentfence (accessed 2026-07-23)
- https://pypi.org/pypi/agentfence/json (accessed 2026-07-23)
- https://arxiv.org/abs/2602.07652 and https://arxiv.org/html/2602.07652v1 (accessed 2026-07-23)
- https://paperswithcode.co/paper/2602.07652 (accessed 2026-07-23)
- https://www.alphaxiv.org/zh/overview/2602.07652v1 (accessed 2026-07-23)
