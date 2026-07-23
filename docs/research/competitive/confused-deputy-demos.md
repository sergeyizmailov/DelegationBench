# Confused-Deputy Demonstrations in LLM Agents (academic demos)

- **Audit date (access/research date):** 2026-07-23
- **Scope:** The audit target is a category, not a single project. The 3 most relevant concrete demonstrations were selected:
  1. **ConfusedPilot** — confused-deputy attacks on RAG-based LLM systems (UT Austin SPARK Lab + Symmetry Systems)
  2. **Imprompter** — adversarial prompts tricking LLM agents into improper tool use (UCSD / U. Wisconsin)
  3. **Multi-Agent Systems Execute Arbitrary Malicious Code** — control-flow hijacking across multi-agent delegation (Cornell Tech, COLM 2025)
- **Alternatives noted:** AgentDojo (prompt-injection benchmark, not confused-deputy-specific), ASB (Agent Security Bench), ToolEmu — all adjacent but further from the confused-deputy/delegation-chain theme.

---

## Project A: ConfusedPilot

### 1. What it is
ConfusedPilot is a class of confused-deputy vulnerabilities in RAG-based LLM systems (demonstrated on Microsoft 365 Copilot, plus open-model RAG setups). An attacker whose only capability is adding a document to an indexed data pool causes the Copilot — which acts with the querying user's access rights — to return corrupted, misattributed, or secret-leaking responses, and to propagate misinformation across the enterprise via cascading document poisoning.

- Canonical URL (no public code repo exists): https://arxiv.org/abs/2408.04870
- Paper: https://arxiv.org/abs/2408.04870 (v1 2024-08-09, v5 2024-10-23)
- Vendor write-ups: https://cloudsecurityalliance.org/articles/confusedpilot-ut-austin-symmetry-systems-uncover-novel-attack-on-rag-based-ai-systems , https://www.symmetry-systems.com/blog/confused-pilot-attack/

### 2. Multi-agent?
**No.** Single RAG assistant. The paper's "cascading attacks" propagate poisoned content between *users* via documents, not between agents delegating to each other.

### 3. Differential privileges?
**Partial (implicit).** The confused-deputy asymmetry is the core of the attack: a low-privilege attacker (write access to a SharePoint/document pool) steers a higher-authority principal (Copilot retrieving with the victim user's permissions, incl. access to confidential docs). But there is no explicit permission model, capability lattice, or per-principal policy — privileges are implicit in the M365 environment.

### 4. Origin tracking?
**No.** The attack works precisely because provenance of retrieved content and the originating user's intent are not tracked. The paper proposes design guidelines (e.g., isolating untrusted content) but implements no origin/identity tracking.

### 5. Chain-wide authority check?
**No.** No authority verification anywhere — that is the demonstrated flaw, not a feature of the work.

### 6. Attack generation?
**No.** Attacks 1–5 are handcrafted malicious strings/prompts embedded in documents. No fuzzing, mutation, or automated generation.

### 7. Exploit minimization?
**No.**

### 8. Regression tests?
**No.** No artifacts emitted; no public code at all.

### 9. ROMA integration?
**No.** No mention of ROMA (sentient-agi).

### 10. Liveness
- No public repository (GitHub search for "confusedpilot" / "confused-pilot" returns 0 repos as of 2026-07-23).
- Paper versions: v1 2024-08-09 → v5 2024-10-23; presented at DEF CON AI Village 2024; ~31 citations.
- Commercial continuation: Symmetry Systems shipped "Confused Pilot Protection" in its Data+AI Security Suite (announced 2025-08-29). The research line is commercially alive, but there is no open-source artifact to track.

### 11. License
**None found** (no code released).

### 12. Overlap verdict
**PARTIAL.** Same conceptual core (confused deputy: low-authority input steers a higher-authority AI acting for someone else), but single-agent RAG only — no multi-agent delegation chains, no differential-permission model, no deterministic oracle, no testbed, no attack generation/minimization/regression-test emission.

---

## Project B: Imprompter

### 1. What it is
Imprompter is an attack + codebase that uses gradient-based optimization to generate obfuscated adversarial prompts which trick tool-using LLM agents into improper, covert tool use — demonstrated as PII exfiltration from Mistral LeChat via disguised markdown-image URL rendering (and on ChatGLM), without alerting the user.

- Canonical URL: https://github.com/Reapor-Yurnero/imprompter
- Paper: https://arxiv.org/abs/2410.14923 (Imprompter: Tricking LLM Agents into Improper Tool Use, Fu et al., 2024)
- Site: https://imprompter.ai/

### 2. Multi-agent?
**No.** Single agent with tools (LeChat, ChatGLM, local GLM4/Mistral-Nemo/Llama3.1). No agent-to-agent delegation.

### 3. Differential privileges?
**Partial (implicit).** The agent holds capabilities (network access, image rendering, file/tools) the text-only attacker lacks — the attacker rides the agent's authority. But no explicit permission model or differing per-agent privilege levels.

### 4. Origin tracking?
**No.** No preservation of originating-user intent/identity; covertness (hiding the exfiltration from the user) is the point.

### 5. Chain-wide authority check?
**No.** Per-conversation attack on one agent; no chain concept.

### 6. Attack generation?
**Yes (partial).** The core contribution is an optimization algorithm that *generates* adversarial prompts (min-heap of top-100 prompts by loss, checkpointable, restartable via `--start_from_file`). This is genuine automated attack synthesis, though it generates prompts against a fixed scenario rather than fuzzing delegation scenarios.

### 7. Exploit minimization?
**No.** It ranks prompts by loss but does not minimize an exploit trace to a shortest reproducer.

### 8. Regression tests?
**No.** It emits evaluation results (pkl/json metrics), not standalone regression tests.

### 9. ROMA integration?
**No.**

### 10. Liveness
- Stars: 54; forks: 5; open issues: 1.
- Commits: 7 total, all between 2024-10-17 and 2024-10-22; last push 2024-10-22.
- Releases: 0. Cadence: one-shot artifact release, dormant since Oct 2024.

### 11. License
**GPL-2.0** (per GitHub API license field).

### 12. Overlap verdict
**PARTIAL.** It has real attack *generation* (a fuzzer-like optimizer), which DelegationBench also wants — but it targets a single agent's improper tool use, with no delegation chains, no differential-privilege model, no origin tracking, no oracle-judged escalation detection, and no minimization/regression emission.

---

## Project C: Multi-Agent Systems Execute Arbitrary Malicious Code (Triedman, Jha, Shmatikov — COLM 2025)

### 1. What it is
A demonstration paper showing that adversarial content (web pages, files, email attachments) can hijack the *control flow and communication* of LLM multi-agent systems, causing the orchestrator to route work into unsafe agents/tools — resulting in arbitrary malicious code execution on the user's device or data exfiltration from the user's container. Attacks succeed at 58–90% (up to 100% in some model-orchestrator pairs) **even when individual agents refuse the harmful action in isolation** — i.e., the delegation graph, not any single agent, is the vulnerability.

- Canonical URL: https://arxiv.org/abs/2503.12188 (v1 2025-03-15, v2 2025-09-12; COLM 2025)
- Author page: https://rishijha.com/pubs/cfh.html — its `[code]` link is empty; no public repository found (GitHub search for the arXiv ID returns 0 repos as of 2026-07-23).

### 2. Multi-agent?
**Yes.** Explicitly targets multi-agent frameworks ("several recently proposed multi-agent frameworks"), hijacking orchestrator routing and inter-agent communication. This is the closest match to DelegationBench's delegation-chain setting.

### 3. Differential privileges?
**Partial.** Agents have heterogeneous capabilities/tools (benign agents vs. agents with code execution, filesystem, network); the attack's essence is chaining low-risk agents into a high-capability one. But privileges are implicit framework features — no formal per-agent permission model is defined or checked.

### 4. Origin tracking?
**No.** The paper demonstrates the absence of origin/intent propagation: the user's original task is benign while the routed agent chain does something the user never asked for. No mechanism is built to track or enforce origin.

### 5. Chain-wide authority check?
**No.** Precisely the gap it exposes: per-agent refusals exist but nothing verifies authority across the whole chain. The paper calls for "trust and security models for multi-agent systems" but does not build one or a testbed for one.

### 6. Attack generation?
**No.** Handcrafted adversarial content and control-flow-hijack payloads, replayed across orchestrators to measure attack success rates. No fuzzer/mutator.

### 7. Exploit minimization?
**No.**

### 8. Regression tests?
**No.**

### 9. ROMA integration?
**No.** No mention of ROMA (sentient-agi).

### 10. Liveness
- No public code repository; paper-only artifact.
- arXiv v1 2025-03-15, v2 2025-09-12; accepted at COLM 2025; actively cited by 2026 follow-on work (e.g., OWASP AISVS C09-08 cites it for control-flow-hijacking requirements).

### 11. License
**None found** (no code released).

### 12. Overlap verdict
**PARTIAL — closest of the three, but not equivalent.** It demonstrates exactly the failure class DelegationBench targets (a delegation chain performing actions the originating user never authorized, with differential agent capabilities), but it is a demonstration, not a testbed: no deterministic oracle, no explicit privilege model, no origin tracking, no attack generation/mutation, no exploit-trace minimization, no regression-test emission, and no reusable open-source harness.

---

## Key quotes / evidence

- ConfusedPilot abstract: "a class of security vulnerabilities of RAG systems that confuse Copilot and cause integrity and confidentiality violations in its responses... a vulnerability that leaks secret data, which leverages the caching mechanism during retrieval." (arXiv:2408.04870)
- ConfusedPilot impact note: "Requires only basic access to manipulate responses by RAG based AI Systems... Can persist even after malicious content is removed." (Cloud Security Alliance, 2024-12-11)
- Imprompter README: "It provides essential components to reproduce and test the attack presented in the paper... The pickle file updates every step during the execution and always stores the current top 100 adversarial prompts." — evidence for attack generation but no minimization/regression emission.
- Triedman et al. abstract: "adversarial content can hijack control and communication within the system to invoke unsafe agents and functionalities... these attacks succeed even if individual agents are not susceptible to direct or indirect prompt injection, and even if they refuse to perform harmful actions." (arXiv:2503.12188)
- OWASP AISVS (2026) framing: "the swarm's routing graph, not the agent's prompt, is the vulnerability."

## Sources

- https://arxiv.org/abs/2408.04870 — ConfusedPilot paper (accessed 2026-07-23)
- https://cloudsecurityalliance.org/articles/confusedpilot-ut-austin-symmetry-systems-uncover-novel-attack-on-rag-based-ai-systems — CSA/Symmetry write-up (accessed 2026-07-23)
- https://www.symmetry-systems.com/blog/confused-pilot-attack/ and https://www.symmetry-systems.com/news/confused-pilot-protection/ — vendor pages (accessed 2026-07-23)
- https://github.com/Reapor-Yurnero/imprompter — Imprompter repo + GitHub API metadata (accessed 2026-07-23)
- https://arxiv.org/abs/2410.14923 — Imprompter paper (accessed 2026-07-23)
- https://arxiv.org/abs/2503.12188 — Multi-Agent Systems Execute Arbitrary Malicious Code (accessed 2026-07-23)
- https://rishijha.com/pubs/cfh.html — author publication page, empty code link (accessed 2026-07-23)
- https://github.com/OWASP/AISVS/blob/main/research/chapters/C09-Orchestration-and-Agents/C09-08-Multi-Agent-Isolation.md — independent characterization (accessed 2026-07-23)
