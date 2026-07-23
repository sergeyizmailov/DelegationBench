# Agent Threat Rules (ATR) — Competitive Audit

- **Canonical repo:** https://github.com/Agent-Threat-Rule/agent-threat-rules
- **Website:** https://agentthreatrule.org (ATD technique catalog at /atd)
- **Paper:** Zenodo DOI 10.5281/zenodo.19178002 (companion paper; LaTeX source at `docs/paper/ATR-Paper.tex` in repo). No arXiv paper found.
- **Access/research date:** 2026-07-23
- **Name ambiguity:** None significant — "Agent Threat Rules" (ATR) is a distinct, single project by Adam Lin (GitHub org `Agent-Threat-Rule`). Not to be confused with generic "agent detection rules" blog content (e.g., Data443/vaikora posts), which are unrelated.

## 1. What it is

ATR is an open, vendor-neutral **detection-rule format and ruleset** for AI-agent security threats — self-described as "what Sigma is to SIEM detection and YARA is to malware signatures," but for AI agents. It ships ~768 YAML rules across 10 categories (prompt injection, agent manipulation, skill compromise, context exfiltration, tool poisoning, privilege escalation, model abuse, excessive autonomy, model security, data poisoning), each rule declaring regex/condition patterns over agent I/O fields (LLM input, tool-call arguments, SKILL.md content, MCP exchanges), plus framework mappings (OWASP LLM/Agentic, MITRE ATLAS, SAFE-MCP, NIST AI RMF). A reference TypeScript engine, Python wrapper (pyATR), CLI, GitHub Action (SARIF), and MCP server evaluate the rules. It is a **detection layer**, not a testbed, benchmark, or attack-generation framework.

## 2. Multi-agent?

**Partial.** ATR *detects within* multi-agent traffic but does not *construct or test* multi-agent delegation scenarios. Evidence: rule `ATR-2026-00074` (`agent_source.type: multi_agent_comm`, frameworks crewai/autogen/langchain) detects cross-agent privilege escalation in inter-agent messages; the ATD catalog covers A2A/inter-agent techniques (OWASP ASI07 insecure inter-agent communication, ASI10 rogue agents); the proposed correlation spec explicitly models A2A delegation chains. But there is no harness that spins up multiple agents and orchestrates delegation between them.

## 3. Differential privileges?

**Partial.** Privilege asymmetry is a *rule topic*, not an engine concept. 35+ rules in `rules/privilege-escalation/` (scope creep, admin-function access, RBAC bypass, cross-agent privesc) and `ATR-2026-00074` pattern-match phrases like "forward my credentials", "acting as the admin agent", "grant this agent elevated permissions". The engine has **no permission/capability model** — it cannot represent that agent A has fewer rights than agent B; it only regex-matches content that *talks about* privilege.

## 4. Origin tracking?

**No.** Nothing preserves the originating user's identity or intent through a chain. Events carry `agent.id` / `session.id` (and the *proposed* correlation spec adds `agent.delegation_chain` as a join key), but there is no notion of "the human who started this chain authorized X, so downstream action Y is out of scope." Detection is per-event content matching.

## 5. Chain-wide authority check?

**No** (with a minor adjacent capability). Default operation is per-event rule evaluation — the README itself states a single-event rule "fires on event 1 … event 5 **independently**, with no connection between them." Two adjacent pieces exist: (a) `src/trace-evaluator.ts`, a shipped evaluator for `detection.method: trace` rules with forbid/require/invariant primitives over OpenInference/OTel GenAI span DAGs — chain-*shape* checks over a trace, but pattern predicates, not authority reasoning; (b) `spec/atr-correlation-v1.0.md`, a Sigma-correlation-style multi-event join spec targeting "delegated authority abuse" chains — but it is explicitly **PROPOSED, NOT RATIFIED, with zero correlation rules shipped**. Neither compares a terminal action against the originating user's authority.

## 6. Attack generation?

**No.** ATR consumes attack corpora produced by others (garak, HackAPrompt, PromptInject, AdvBench, HarmBench, hh-rlhf, wild skill-registry scans) to *measure recall* of its rules. It has no fuzzer, mutator, or attack synthesizer. (`atr scaffold` generates rule *boilerplate*, not attacks.)

## 7. Exploit minimization?

**No.** No trace minimization, delta-debugging, or shortest-reproducer logic anywhere in the repo. Each rule ships fixed hand-written `test_cases` (true/false positives) and documented `evasion_tests`.

## 8. Regression tests?

**No** (as an output of findings). Each rule bundles its own `test_cases` used by `atr test` / vitest — these are rule self-tests, not standalone regression tests generated from discovered exploits. The README's "Featured loop" story about regression-test fixtures (CVE-2026-26030/25592) describes fixtures written by *Microsoft Copilot inside Microsoft's agent-governance-toolkit*, not an ATR capability.

## 9. ROMA integration?

**No.** No mention of ROMA (sentient-agi) in the repo, README, adoption list, or integration PRs. Adoption targets are Microsoft AGT, Cisco AI Defense, MISP/CIRCL, Gen Digital Sage, OWASP, with open PRs to garak, PyRIT, LiteLLM, promptfoo, PurpleLlama, etc.

## 10. Liveness (as of 2026-07-23)

- **Stars:** 347 · **Forks:** 47 · **Primary language:** TypeScript
- **Created:** 2026-03-09 · **Last push:** 2026-07-23 (same day as audit)
- **Commit cadence:** Very high — effectively daily commits (30 most recent commits span 2026-07-13 → 2026-07-23, multiple per day)
- **Latest release:** v3.5.11 "768 detection rules", published 2026-07-14; frequent release train (v2.x → v3.5.x since March 2026)
- **Open issues:** 1 (per GitHub API at audit time; many integration *PRs* open on other projects)
- Single-maintainer (BDFL, Adam Lin) with TSC transition planned; sponsorship via Open Collective.

## 11. License

**MIT** (SPDX `MIT`) — stated in README §15, GitHub license field, and CITATION.cff. Note: older integration-proposal issues from May 2026 describe the project as Apache-2.0; the license was apparently changed to MIT at some point. Current repo is unambiguously MIT.

## 12. Overlap verdict

**PARTIAL — adjacent threat class, different layer and method.** ATR is the closest detection-side project to DelegationBench's threat model: it has an explicit cross-agent privilege-escalation rule (`ATR-2026-00074`, severity critical, OWASP ASI03/ASI10 mappings) and a *proposed* correlation format aimed at exactly the "delegated authority abuse" chain. But the overlap stops at topic:

- ATR is a **runtime content detector** (regex over agent messages), DelegationBench is a **testbed with a deterministic authorization oracle**.
- Missing vs DelegationBench: executable multi-agent delegation scenarios, a differential-privilege model, originating-user intent/identity propagation, chain-wide authority checking (ATR's own docs concede per-event independence; correlation is unratified), attack generation, exploit-trace minimization, and regression-test emission.
- Not a direct equivalent and not a project-killer; if anything, ATR is a potential *consumer* of DelegationBench findings (new rules) or a detection baseline to evaluate against.

## Key quotes / evidence

- "ATR is to AI-agent threat detection what Sigma is to SIEM detection and YARA is to malware signatures." (README Abstract)
- Privilege Escalation category: "Scope creep, delayed execution bypass, admin function access, shell escape, SQL injection in admin endpoints" — 35 rules (README §7).
- `ATR-2026-00074` description: "Attackers exploit multi-agent architectures by having a compromised or lower-privilege agent forward credentials, assume roles of higher-privilege agents, or bypass orchestrator controls through direct agent-to-agent messaging." — detection is six English regexes over `content`.
- Same rule's own evasion tests concede bypass by Spanish translation, casual paraphrase ("hand over my creds"), and split keywords — i.e., it is a content filter, not an authority check.
- Correlation spec: "**STATUS: PROPOSED v1.0 — NOT YET RATIFIED.** … No correlation rules have shipped to the canonical corpus yet." Its motivation paragraph admits single-event rules fire "independently, with no connection between them."
- README §8: "ATR is honest about what it cannot detect. Regex catalogs miss paraphrased attacks … pair with credential brokering, sandbox execution, and human-in-the-loop for high-blast-radius actions."

## Sources

- [github.com/Agent-Threat-Rule/agent-threat-rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) — README, repo metadata via GitHub API (accessed 2026-07-23)
- [rules/agent-manipulation/ATR-2026-00074-cross-agent-privilege-escalation.yaml](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/agent-manipulation/ATR-2026-00074-cross-agent-privilege-escalation.yaml) (accessed 2026-07-23)
- [spec/atr-correlation-v1.0.md](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/spec/atr-correlation-v1.0.md) (accessed 2026-07-23)
- [src/trace-evaluator.ts](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/src/trace-evaluator.ts) (accessed 2026-07-23)
- [Zenodo DOI 10.5281/zenodo.19178002](https://doi.org/10.5281/zenodo.19178002) — companion paper (cited from README §12, accessed 2026-07-23)
- [Help Net Security coverage, 2026-06-03](https://www.helpnetsecurity.com/2026/06/03/agent-threat-rules-ai-detection/) (accessed 2026-07-23)
- Release v3.5.11: https://github.com/Agent-Threat-Rule/agent-threat-rules/releases/tag/v3.5.11 (accessed 2026-07-23)
