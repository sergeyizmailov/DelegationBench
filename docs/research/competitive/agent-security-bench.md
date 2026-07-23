# Agent Security Bench (ASB)

- **Canonical repo:** https://github.com/agiresearch/ASB
- **Paper:** https://arxiv.org/abs/2410.02644 (ICLR 2025, OpenReview: https://openreview.net/forum?id=V4y0CpX4hK)
- **Project site:** https://luckfort.github.io/ASBench/
- **Access/research date:** 2026-07-23 (UTC)

## 1. What it is

ASB is an academic benchmark (ICLR 2025, Rutgers et al.) that formalizes and evaluates attacks and defenses against LLM-based agents. It ships 10 task scenarios (e-commerce, autonomous driving, finance, legal advice, etc.), 10 agents, 400+ tools, 27 attack/defense methods, and 7 metrics; attacks include direct/observation prompt injection (DPI/OPI), memory poisoning, a Plan-of-Thought backdoor, and mixed attacks. It is built on top of the AIOS agent runtime (same research group, agiresearch org).

## 2. Multi-agent?

**No.** Each of the 10 scenarios is a single agent with a tool set. There is no agent-to-agent delegation topology. Full-text search of the paper (arXiv HTML, v3) returns zero hits for "multi-agent" and "delegat*".

## 3. Differential privileges?

**No.** Agents are not modeled with differing permission levels. All tool access within a scenario is effectively uniform; attacks aim to make the agent call an attacker-chosen "target tool," not to cross a privilege boundary. Zero hits for "privilege" / "permission" in the paper.

## 4. Origin tracking?

**No.** There is one user per scenario whose prompt may be compromised; ASB does not track an originating user's intent/identity through any chain (there is no chain).

## 5. Chain-wide authority check?

**No.** Success is judged per-run by whether the attacker's injected instruction/tool call was executed (attack success rate, and a utility-vs-security balancing metric). There is no notion of verifying authority across a delegation chain; checks are per-agent/per-task.

## 6. Attack generation?

**Partial.** ASB implements a fixed library of 10 prompt-injection attack techniques (e.g., from published work), memory poisoning, PoT backdoor, and 4 mixed combinations — attacker prompts are templated/parameterized over scenarios and target tools. It is not fuzzer-like: no mutation loop, no search over attack space, no novel-attack synthesis. Attacks are curated, not generated.

## 7. Exploit minimization?

**No.** No trace minimization or shortest-reproducer functionality anywhere in the repo or paper.

## 8. Regression tests?

**No.** ASB outputs benchmark metrics (ASR, FNR/FPR, benign performance, etc.), not standalone regression test cases derived from findings.

## 9. ROMA integration?

**No.** The runtime dependency is AIOS (`aios/`, `pyopenagi/` in repo root), from the same agiresearch group. No mention of ROMA / sentient-agi anywhere.

## 10. Liveness

- **Stars:** 273; **forks:** 29 (as of 2026-07-23)
- **Last commit:** 2026-04-16 ("Solve the too_calling bug in llama")
- **Commit cadence:** sparse/bursty — gaps of months (2025-05 → 2025-10 → 2026-04); typical academic-benchmark maintenance
- **Open issues:** 4 (3 user-reported, e.g. "main_attack.py always hangs on tasks reaching step 9 in workflow plans", Oct 2025)
- **Last release:** none (no GitHub releases; versioning via arXiv v1–v4, latest v4 2025-05-30)

## 11. License

**MIT** (LICENSE file present; GitHub API reports SPDX `MIT`).

## 12. Overlap verdict: PARTIAL

ASB overlaps DelegationBench only in the broad sense of "benchmark that runs attacks against LLM agents and checks outcomes." Its threat model is prompt injection / memory poisoning / backdoors against a **single** agent, judged by attack success rate. Everything that defines DelegationBench is absent: no multi-agent delegation topology, no differential privilege levels between agents, no originating-user intent tracking, no chain-wide authority oracle, no attack fuzzing/mutation engine, no exploit-trace minimization, and no regression-test emission. ASB is a related-but-orthogonal benchmark; it does not kill the project. It is, however, a natural citation for the "agent attack benchmarks exist but none model delegation privilege escalation" gap statement, and its scenario/tool data could be reused as attack substrate.

## Key quotes/evidence

- Abstract: "we introduce Agent Security Bench (ASB), a comprehensive framework designed to formalize, benchmark, and evaluate the attacks and defenses of LLM-based agents, including 10 scenarios … 10 agents … over 400 tools, 27 different types of attack/defense methods, and 7 evaluation metrics."
- README: "The LLM Agent Attacking Framework includes DPI, OPI, Plan-of-Thought (PoT) Backdoor, and Memory Poisoning Attacks, which can compromise the user query, observations, system prompts, and memory retrieval of the agent during action planning and execution."
- README: "The development of ASB is based on AIOS."
- Paper full-text grep (v3 HTML): 0 hits for `multi-agent`, `delegat`, `privilege`, `permission`.
- GitHub API (2026-07-23): `stargazers_count: 273`, `pushed_at: 2026-04-16`, `open_issues_count: 4`, `license.spdx_id: MIT`, no releases.

## Sources

- https://github.com/agiresearch/ASB — accessed 2026-07-23
- https://arxiv.org/abs/2410.02644 and https://arxiv.org/html/2410.02644v3 — accessed 2026-07-23
- https://api.github.com/repos/agiresearch/ASB (repo metadata, commits, issues, releases) — accessed 2026-07-23
- https://luckfort.github.io/ASBench/ — referenced from README, 2026-07-23

Note on ambiguity: "ASB" here unambiguously refers to the ICLR 2025 Agent Security Bench by Zhang et al. (Rutgers/agiresearch). A name-collision exists with "Agent SafetyBench" (different paper/benchmark); that was not audited here.
