# AgentDojo — Competitive Audit for DelegationBench

- **Project:** AgentDojo
- **Canonical repo:** https://github.com/ethz-spylab/agentdojo
- **Docs/site:** https://agentdojo.spylab.ai (also mirrored at https://ethz-spylab.github.io/agentdojo/)
- **Paper:** "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents" — https://arxiv.org/abs/2406.13352 (NeurIPS 2024 Datasets & Benchmarks)
- **Authors/org:** ETH Zurich SPY Lab + Invariant Labs (Debenedetti, Zhang, Balunović, Beurer-Kellner, Fischer, Tramèr)
- **Access/research date:** 2026-07-23 (UTC)

## 1. What it is

AgentDojo is an extensible evaluation framework for measuring the adversarial robustness of LLM agents that call tools over untrusted data, focused on **prompt-injection attacks and defenses**. It ships 97 realistic user tasks across 4 suites (workspace, banking, travel, slack) and 629 security test cases, plus pluggable attack and defense paradigms. Evaluation is trace-based: user-task *utility* and injection-task *security* are scored by deterministic checks against ground truth, not by an LLM judge.

## 2. Multi-agent?

**No.** Each task runs a single LLM agent (one `agent_pipeline`) with a set of tools. There is no agent-to-agent delegation, no supervisor/worker topology, no multi-hop chains. Repo source tree contains no delegation/multi-agent modules (`src/agentdojo/` subdirs: `agent_pipeline`, `attacks`, `data`, `default_suites`, `scripts`, `task_suite`).

## 3. Differential privileges?

**No (partial at most, as defense surface).** All tools in a suite are available to the one agent with uniform authority. Some *defenses* restrict capabilities (e.g., `tool_filter` limits which tools are callable, and follow-up work like CaMeL/progent-style policies builds on AgentDojo), but the benchmark itself does not model agents or roles with differing permissions.

## 4. Origin tracking?

**No.** There is a single originating user whose task is fixed per test case. The attacker's injected instruction arrives via tool-returned data; AgentDojo tracks this only as a ground-truth label for scoring (did the injection goal get executed?), not as identity/intent propagation through a chain. There is no chain to propagate through.

## 5. Chain-wide authority check?

**No.** Security is evaluated per single-agent episode: did the agent execute the attacker's goal function calls? Checks are per-tool-call-trace against ground truth, not authority validation across a delegation chain (none exists). This is the core gap vs DelegationBench.

## 6. Attack generation?

**Partial.** AgentDojo has an attack registry (`load_attack`/`register_attack`) and several attack families (`important_instructions`, `tool_knowledge`, `ignore_previous`, `injecagent`, `dos_attacks`) that render the attacker's goal into injection text placed at environment placeholders. It is a *pluggable attack framework*, not a fuzzer — attacks are fixed templates with the goal string substituted, not mutated/evolved automatically.

## 7. Exploit minimization?

**No.** No mechanism to reduce a successful attack trace to a minimal reproducer.

## 8. Regression tests?

**No.** Results are logged/inspectable pipelines (and mirrored to the Invariant Benchmark Registry), but AgentDojo does not emit standalone regression tests from findings. The benchmark tasks themselves are reusable, but there is no finding → test-case export.

## 9. ROMA integration?

**No.** No reference to ROMA (sentient-agi) in the repo or paper.

## 10. Liveness (as of 2026-07-23)

- **Stars:** 678 — **Forks:** 176 — **Open issues:** 37
- **Last commit:** 2026-06-02 ("Add openai-compatible provider for arbitrary OpenAI-compatible endpoints (#147)") — ~7 weeks before access date
- **Commit cadence:** sporadic bursts with multi-month gaps (2026-06, 2026-03, 2026-02, 2025-10); repo not archived, still maintained
- **Last release:** v0.1.35 (2025-10-27); releases are infrequent (v0.1.33–v0.1.35 since 2025-05)
- **PyPI:** `pip install agentdojo`

## 11. License

**MIT** (SPDX: MIT, per repo LICENSE / GitHub API).

## 12. Overlap verdict

**PARTIAL.** AgentDojo shares DelegationBench's *family* — a benchmark for security failures of tool-using LLM agents, with (mostly) deterministic trace-based oracles and a pluggable attack framework. But the threat model is disjoint: AgentDojo tests **single-agent prompt injection** (untrusted tool data hijacks one agent), while DelegationBench targets **privilege escalation across multi-agent delegation chains**. Missing: multi-agent scenarios, differential privileges per agent, origin/intent propagation, chain-wide authority checks, attack mutation/fuzzing, exploit minimization, and regression-test emission. AgentDojo does not kill DelegationBench; if anything it validates the deterministic-oracle evaluation design and is a plausible substrate/comparison baseline.

## Key quotes/evidence

- Paper abstract: "we introduce AgentDojo, an evaluation framework for agents that execute tools over untrusted data... not a static test suite, but rather an extensible environment for designing and evaluating new agent tasks, defenses, and adaptive attacks. We populate the environment with 97 realistic tasks... 629 security test cases."
- Repo description: "A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents."
- Source tree: single `agent_pipeline`; attack families are template renderers (`FixedJailbreakAttack`, `BaseAttack`) registered in an attack registry — pluggable but not generative.
- GitHub API (2026-07-23): 678 stars, 176 forks, 37 open issues, pushed_at 2026-06-02, license MIT.

## Sources

- https://github.com/ethz-spylab/agentdojo — accessed 2026-07-23
- https://arxiv.org/abs/2406.13352 — accessed 2026-07-23
- https://agentdojo.spylab.ai — accessed 2026-07-23
- https://api.github.com/repos/ethz-spylab/agentdojo (stars/commits/releases/license) — accessed 2026-07-23
