# AgentFuzz — Competitive Audit for DelegationBench

- **Project:** AgentFuzz ("Make Agent Defeat Agent")
- **Canonical repo:** https://github.com/LFYSec/AgentFuzz
- **Paper:** *Make Agent Defeat Agent: Automatic Detection of Taint-Style Vulnerabilities in LLM-based Agents*, USENIX Security 2025 (Liu et al., Fudan University / UC Davis) — https://www.usenix.org/conference/usenixsecurity25/presentation/liu-fengyu · PDF: https://lfysec.github.io/paper/agentfuzz-security25.pdf · Artifact archive: https://zenodo.org/records/15590097
- **Access/research date:** 2026-07-23 (UTC)
- **Name ambiguity:** None significant. This is the only established project named "AgentFuzz"; the USENIX Sec'25 paper's repo is unambiguous.

## 1. What it is

AgentFuzz is a directed greybox fuzzing framework for detecting **taint-style vulnerabilities** in LLM-based agents — i.e., cases where a malicious user prompt flows unsanitized through the agent into a security-sensitive sink (`eval()`, SQL, command execution, SSRF), enabling code/SQL/command injection. It works in three phases: LLM-assisted generation of functionality-specific natural-language seed prompts (guided by statically extracted sink call chains), multifaceted feedback-driven seed scheduling (semantic + CFG-distance scoring), and sink-guided mutation (functionality + argument mutators). Detection uses **predefined vulnerability oracles** (instrumentation-based sink-trigger checks — deterministic, not an LLM judge). Evaluated on 20 real-world open-source agent applications; found 34 0-day vulnerabilities, 23 CVEs assigned. USENIX Security '25 artifact badges: Available + Evaluated.

## 2. Multi-agent?

**No.** AgentFuzz tests individual single-agent applications that expose web services (e.g., TaskWeaver). There is no scenario where multiple agents delegate tasks to each other. The "Make Agent Defeat Agent" title refers to using LLM-driven fuzzing logic against a target agent, not to agent-to-agent delegation.

## 3. Differential privileges?

**No.** There is no permission/capability model distinguishing actors. The threat model has a single class of attacker (a malicious user, remote or local) versus a benign agent; "privilege escalation" in the paper means the attacker gaining code execution on the agent's host/container — classic attacker-vs-host privilege, not differing authority levels between agents.

## 4. Origin tracking?

**No.** The originating user's intent/identity is not modeled or preserved. Taint tracking is data-flow based (prompt substring → sink argument); there is no notion of a principal whose authorization scope must survive the chain.

## 5. Chain-wide authority check?

**No.** The oracle checks whether a specific predefined sink callsite was triggered with attacker-controlled data — a per-call-chain source-to-sink check. There is no authority/authorization check, chain-wide or otherwise.

## 6. Attack generation?

**Yes — this is its core.** LLM-assisted seed generation from sink call-chain semantics, feedback-driven scheduling, and two mutators (functionality mutator, argument mutator) that refine prompts until they trigger the sink. A genuine fuzzer architecture (seed pool, scheduling, mutation loop, PoC output).

## 7. Exploit minimization?

**No.** Successful mutated prompts are output as PoCs, but there is no trace/exploit minimization to a shortest reproducer. Nothing in the paper or repo describes delta-debugging-style reduction.

## 8. Regression tests?

**No.** Output is PoC prompts and fuzz logs (plus CVE reporting), not standalone regression tests emitted from findings.

## 9. ROMA integration?

**No.** No reference to ROMA (sentient-agi) anywhere in the repo or paper.

## 10. Liveness

- **Stars:** 94 · **Forks:** 9 (as of 2026-07-23, GitHub API)
- **Repo created:** 2025-07-02 · **Last push:** 2026-04-13
- **Commit cadence:** 4 commits total — an academic artifact dump with occasional fixes, not active development
- **Open issues:** 0 (3 closed: CodeQL version request, path-condition question, vulnerability-confirmation question)
- **Releases:** none on GitHub; v1 snapshot on Zenodo (2025-06-06, files access-restricted)

## 11. License

**None found.** No LICENSE file in the repo root, GitHub API reports `license: null`, Zenodo record lists no license either. (Not open-source licensed despite public code — relevant for reuse.)

## 12. Overlap verdict

**PARTIAL — not a threat to DelegationBench.**

Overlap exists in two dimensions: (a) **attack generation** — AgentFuzz is a true fuzzer that generates/mutates attack prompts, and (b) **deterministic oracle** philosophy — sink-triggered detection via instrumentation rather than an LLM judge. But AgentFuzz answers a different question: *can attacker-controlled prompt text reach a dangerous code sink in a single agent?* It has no multi-agent delegation model, no differential privileges between agents, no originating-user intent/identity tracking, no chain-wide authority verification, no exploit-trace minimization, and no regression-test emission. DelegationBench's core claim (privilege escalation *across delegation chains*, judged chain-wide against the originating user's authorization) is entirely absent. AgentFuzz is closer to an adjacent technique (fuzzing harness + deterministic oracle design) worth citing as related work than a competitor.

## Key quotes/evidence

- "the first fuzzing framework for detecting taint-style vulnerabilities in LLM-based agents" (abstract)
- "We consider attackers to be malicious users who possess the capability to interact with an agent under normal operational conditions. By sending crafted prompts to the agent, an attacker could control the execution of a sensitive function (i.e., sink) and gain unauthorized privileges." (§2.2.2 Threat Model)
- "we evaluated it on 20 widely used open-source agent applications that provide web services" — targets are single-agent web services, no delegation chains (§1)
- "our approach executes the mutated seeds in the agent and uses predefined vulnerability oracles to determine if they trigger the sink, outputting successful prompts as vulnerability PoCs" (§4.2) — deterministic oracle, PoC output only
- Repo README workflow: CodeQL static analysis → instrumentation (`cetracer.py`) → fuzzing via Playwright PoC scripts against a running app — confirms single-target, sink-triggered model.

## Sources

- https://github.com/LFYSec/AgentFuzz (repo, README, license check via GitHub API) — accessed 2026-07-23
- https://www.usenix.org/conference/usenixsecurity25/presentation/liu-fengyu — accessed 2026-07-23
- https://lfysec.github.io/paper/agentfuzz-security25.pdf (full paper) — accessed 2026-07-23
- https://zenodo.org/records/15590097 (artifact archive) — accessed 2026-07-23
- https://api.github.com/repos/LFYSec/AgentFuzz (+ /commits, /issues, /releases, /license) — accessed 2026-07-23
