# ChainFuzzer — Competitive Audit

- **Project:** ChainFuzzer: Greybox Fuzzing for Workflow-Level Multi-Tool Vulnerabilities in LLM Agents
- **Authors:** Jiangrong Wu, Zitong Yao, Yuhong Nan, Zibin Zheng (Sun Yat-sen University)
- **Paper:** https://arxiv.org/abs/2603.12614 (v1, 13 Mar 2026)
- **Code/artifact:** NONE FOUND. GitHub repo search for "ChainFuzzer" returns 0 results; the paper's artifact statement is an unresolved placeholder ("we have released the corresponding artifact: xxx"). No public implementation located.
- **Access/research date:** 2026-07-23

## 1. What it is

ChainFuzzer is a greybox fuzzing framework that discovers *multi-tool* vulnerabilities in tool-augmented LLM agents: exploitable source-to-sink dataflows (CMDi, CODEi, SSRF, SSTI, SQLi) that only emerge when tools are composed into multi-step workflows (e.g., web_search → download → write_file → execute). It extracts candidate tool chains by backward analysis from sink tools, synthesizes stable prompts that drive the agent along a target chain (Trace-guided Prompt Solving), and reproduces vulnerabilities under LLM guardrails via payload mutation with sink-specific deterministic oracles. Evaluated on 20 popular open-source agent apps (998 tools): 365 unique reproducible vulnerabilities across 19/20 apps, 302 of them multi-tool.

## 2. Multi-agent?

**No.** The "chains" are *tool-call chains within a single agent*, not chains of agents delegating to each other. There is no notion of one agent handing a task to another. (Some evaluated targets, e.g. MetaGPT, are multi-agent frameworks, but ChainFuzzer treats each app as one agent with a tool set; no inter-agent delegation is modeled.)

## 3. Differential privileges?

**No.** No permission/capability model. Tools are classified only by whether they contain a sink API (exec/eval/urlopen/SQL/template) reachable from tool inputs. There is no concept of one principal having more authority than another.

## 4. Origin tracking?

**No (partial at best).** It distinguishes *injection source* (user-driven vs environment-driven payload injection) as an attack classification, but does not preserve an originating user's identity or authorized intent through the workflow to compare against the final action. "Untrusted content" is the threat model, not "unauthorized relative to originator."

## 5. Chain-wide authority check?

**No.** Oracles are *sink-specific effect detectors* (sink API reached with payload-influenced argument; probe effect observed) — deterministic, but they check taint-reachability of a dangerous call, not whether the end-to-end chain exceeded the authority granted by the originating user. No per-principal or chain-wide authorization semantics.

## 6. Attack generation?

**Yes.** This is its core strength: candidate-chain extraction, LLM-based seed/valid prompt synthesis (TPS with trace-guided iterative repair), and guardrail-aware payload mutation (sharding into benign fragments, base64/escape encoding, format perturbation). Mutation lifts trigger rate from 18.20% → 88.60%.

## 7. Exploit minimization?

**Partial.** The paper claims output of "minimal, auditable PoCs with tool-call traces and effect evidence," and PoCs are compact by construction (prompt + payload + trace). However, there is no described minimization algorithm (no delta-debugging / trace-shortening pass that reduces a found exploit to a shortest reproducer); "minimal" refers to the PoC format, not an automated reduction procedure.

## 8. Regression tests?

**No.** Output is a PoC bundle (triggering prompt, malicious payload, tool-call trace, oracle evidence) for developer reporting — not standalone, re-runnable regression tests generated from findings.

## 9. ROMA integration?

**No.** No mention of ROMA (sentient-agi) anywhere in the paper.

## 10. Liveness

- **Repo:** none found (artifact placeholder in paper, GitHub search returns 0 repos).
- **Paper:** arXiv v1 submitted 2026-03-13; cited by ~4 (per arXiv listing).
- **Stars/commits/issues/releases:** N/A — no public code. Activity signals limited to the single preprint.

## 11. License

**None found.** No repository, no LICENSE file. The arXiv preprint itself is under arXiv's non-exclusive distribution license, which does not cover any implementation.

## 12. Overlap verdict

**PARTIAL.** ChainFuzzer shares DelegationBench's machinery of attack generation/fuzzing, deterministic (non-LLM) sink oracles, and reproducible exploit traces — and its prompt-stabilization (TPS) and guardrail-mutation techniques are directly reusable ideas. But it is a *vulnerability-discovery framework against real agent apps*, not a *benchmark/testbed*, and it entirely lacks DelegationBench's core problem: there is no multi-agent delegation, no differential privilege model, no origin-intent tracking, and no chain-wide authority checking — its oracle is classic taint-to-sink, not authorization-relative-to-originator. It also does not emit regression tests, and (currently) has no released code. It is a complementary offensive tool, not an equivalent.

## Key quotes/evidence

- "We study this risk as multi-tool vulnerabilities in LLM agents ... exploitable source-to-sink dataflows that only emerge through tool composition." (Abstract)
- "a tool is labeled as a sink_tool only if at least one sink callsite receives an argument that can be influenced by the tool's entry inputs" (§4.1.1 — taint model, not authority model)
- "ChainFuzzer applies sink-specific oracles based on observable tool effects and trace evidence, producing a minimal PoC trace for reporting." (§3.2)
- "If malicious payload is block by the guardrail of the LLM, ChainFuzzer mutates the payload ... (i) shard ... (ii) encode ... (iii) perturb format" (§4.3.2)
- "To faciliate [sic] future research, we have released the corresponding artifact: xxx." (§1 — unresolved placeholder)
- Scope: "we do not assume an attacker can modify the agent code ... beyond the permissions already granted to the agent tools." (§2.2 — permissions are static, not differentiated per principal)

## Sources

- https://arxiv.org/abs/2603.12614 — abstract page (accessed 2026-07-23)
- https://arxiv.org/html/2603.12614v1 — full text (accessed 2026-07-23)
- GitHub repository search API (`q=ChainFuzzer`) — 0 results (accessed 2026-07-23)
