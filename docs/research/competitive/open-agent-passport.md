# Open Agent Passport (OAP) — Competitive Audit

- **Project:** Open Agent Passport (OAP), by APort Technologies Inc. (Uchi Uchibeke)
- **Canonical URLs:** https://github.com/aporthq/aport-spec (spec) · https://github.com/aporthq/aport-agent-guardrails (reference impl) · https://aport.io
- **Paper:** ["Before the Tool Call: Deterministic Pre-Action Authorization for AI Agents"](https://arxiv.org/abs/2603.20953) (arXiv:2603.20953, v1 2026-03-21); spec DOI: 10.5281/zenodo.18901596
- **Access/research date:** 2026-07-23
- **Name ambiguity note:** "Agent Passport" is a crowded name. Distinct projects include Agent Passport System (agent-passport.org, APS — delegation receipts, monotonic narrowing) and Cubitrek's Agent Passport (signed JSON at `/.well-known/agent-passport.json`). The match for "Open Agent Passport" is unambiguous: the APort/OAP project above, which uses that exact name.

## 1. What it is

OAP is an open specification plus reference implementation for **pre-action authorization** of AI-agent tool calls: a `before_tool_call` framework hook intercepts every tool call, evaluates it deterministically against a declarative policy pack and a cryptographically signed "passport" credential (Ed25519) binding agent identity to a capability scope and limits, and emits a signed audit record. It is enforcement infrastructure (a "runtime trust rail"), not a benchmark or testbed — though the authors run a live human-attacker CTF ("APort Vault", banking domain, $5,000 bounty) as evaluation evidence.

## 2. Multi-agent?

**Partial (spec-only).** The paper (v1.0) explicitly admits: *"OAP v1.0 does not formalize a delegation model for multi-agent scenarios."* However, the spec repo gained `oap/delegation.md` — "OAP Delegation Chains" working draft (dated 2026-03-15, committed 2026-04-13) — which fully specifies multi-agent delegation: orchestrator → worker chains, re-delegation, depth caps (1–8). But it is a **working draft with no reference implementation**: the flagship `aport-agent-guardrails` repo (388 files) contains zero delegation code, and the Vault CTF testbed is single-agent ("generalization to … multi-agent delegation is not demonstrated" — paper §6.1).

## 3. Differential privileges?

**Yes.** This is the core of the design. Each agent holds a passport with its own capability set and limits (`currency_limits`, `allowed_domains`, `allow_pii`, rate limits); six assurance levels (L0–L4FIN) gate sensitive policy packs. The delegation spec enforces that a delegate's effective capabilities are the *intersection* of its own passport and the granted scope — so agents genuinely differ in permissions.

## 4. Origin tracking?

**Yes (spec-only).** The Delegation Chains spec propagates `chain_root_passport_id` unchanged through the entire chain ("Passport ID of the root principal; propagated unchanged through entire chain") and mandates audit records containing `chain_root_passport_id`, `delegation_chain_ids`, and `acting_agent_id` for forensic reconstruction. Caveat: the `purpose` field (closest thing to user *intent*) is explicitly advisory — enforcement adapters "MAY use this for logging" and unsigned `metadata` "MUST NOT affect authorization decisions." Origin *identity* is tracked; origin *intent* is documented, not enforced. Not implemented in the reference SDK.

## 5. Chain-wide authority check?

**Yes (spec-only).** `verifyDelegationChain()` in the delegation spec validates the **whole chain** on every action: ordered root-to-leaf linkage, per-link Ed25519 signature verification, scope-narrowing at every hop (`OAP-D-001: SCOPE_EXCEEDS_DELEGATOR`), limits-monotonicity via recursive `limitsWithinParent`, depth consistency, immutable `depth_cap`, and **cascade revocation** ("checking ALL tokens in chain, not just the leaf"). This is exactly a confused-deputy defense. Two caveats: (a) it exists only as a spec draft; (b) the deployed per-call policy engine "evaluates each tool call independently" and the paper concedes sequence/"structuring" attacks are unhandled (sliding-window packs planned for v1.1).

## 6. Attack generation?

**No.** The adversarial evaluation is a human-attacker CTF (1,151 sessions, 4,437 decisions, $5,000 bounty). No fuzzer, no automated attack mutation/generation anywhere in the paper or repos.

## 7. Exploit minimization?

**No.** No trace minimization, delta-debugging, or shortest-reproducer tooling.

## 8. Regression tests?

**No (in DelegationBench's sense).** The repo has a conformance suite (`conformance/` runner with allow/deny test cases per policy pack), but it validates *implementations against the spec* — it does not emit standalone regression tests from discovered exploits/findings.

## 9. ROMA integration?

**No.** No mention of ROMA / sentient-agi in the paper, spec, or repos. Integrations target LangChain, CrewAI, Claude Code, OpenClaw, Mastra, n8n, DeerFlow, MCP.

## 10. Liveness (as of 2026-07-23, GitHub API)

| Repo | Stars | Last push | Open issues |
|---|---|---|---|
| aporthq/aport-agent-guardrails (flagship) | 25 | 2026-07-19 | 1 |
| aporthq/aport-spec | 4 | 2026-07-19 | 5 |
| aporthq/aport-integrations | 4 | 2026-07-19 | 91 |
| aporthq/mcp-policy-gate-example | 0 | 2026-07-20 | 1 |

- **Cadence:** actively maintained — multiple org repos pushed within 4 days of the audit date; spec commits from Feb through Jul 2026 (delegation spec added 2026-04-13).
- **Releases:** no GitHub releases on the spec repo; releases ship via npm — `@aporthq/aport-agent-guardrails` v1.0.29 (first published 2026-02-19, registry last modified 2026-05-28).
- Small community (≤25 stars) but commercially backed (APort Technologies Inc.; live vault.aport.io CTF).

## 11. License

**Mixed / inconsistent across artifacts:**
- `aport-spec` LICENSE file: **MIT** (Copyright APort Technologies Inc.) — yet the paper and README claim the spec is "released under Apache 2.0" (Zenodo DOI). Discrepancy worth noting.
- `@aporthq/aport-agent-guardrails` (npm): **Apache-2.0** (GitHub flags the repo license as NOASSERTION).
- `aport-integrations`, `aport-sdks-and-middlewares`, `aport.id`: MIT. `aport-skills`: Apache-2.0. Several smaller repos: no license.
- Paper itself: CC BY 4.0.

## 12. Overlap verdict: **PARTIAL**

OAP operates in DelegationBench's exact problem *domain* — it even names the failure mode ("scope escalation … the 'confused deputy' problem", "chain opacity") and specifies chain-wide authority verification with root-principal tracking. But it is **enforcement infrastructure, not a detection benchmark**, and the parts closest to DelegationBench are the least mature:

- Delegation chains: spec draft only (v1.0.0 Working Draft), zero implementation in the reference SDK, zero test scenarios.
- No attack generation/fuzzing (human CTF only, single-agent banking domain).
- No deterministic oracle comparing outcomes against originating-user *intent* — OAP checks policy compliance, not whether the root principal authorized the *specific* action; `purpose` is advisory text.
- No exploit-trace minimization, no regression-test emission.

Nothing here kills DelegationBench; OAP is better viewed as a plausible **target system** whose chain verifier could be fuzzed by DelegationBench. The closest conceptual competitor on the enforcement side remains OAP's own cited rival PCAS (also per-agent, not chain-focused).

## Key quotes/evidence

- "OAP v1.0 does not formalize a delegation model for multi-agent scenarios. An agent that delegates to a sub-agent with narrowed permissions requires a delegation chain specification. This is planned for v1.1." — paper §8.1
- "Scope escalation — a sub-agent acquires capabilities that were never intended (the 'confused deputy' problem)" / "Chain opacity — the authorizing system cannot trace which root principal authorized a downstream action" — `oap/delegation.md`, Abstract
- "Note on cascade revocation: Step 6 checks all tokens in the chain for revocation, not just the leaf." — `oap/delegation.md` §3.2
- "OAP evaluates each tool call independently. A sequence of individually-permitted calls could collectively achieve an unauthorized outcome." — paper §8.1
- "The Vault tests a single domain (banking); generalization to code execution or multi-agent delegation is not demonstrated." — paper §6.1
- "social engineering succeeded against the model 74.6% of the time under a permissive policy; under a restrictive OAP policy … 0% success rate across 879 attempts" — paper abstract
- Reference SDK (`aport-agent-guardrails`, 388 files) contains no delegation-related files — spec-only feature confirmed via GitHub tree API, 2026-07-23.

## Sources

- [arXiv:2603.20953 — Before the Tool Call: Deterministic Pre-Action Authorization for AI Agents](https://arxiv.org/abs/2603.20953) (full text: https://arxiv.org/html/2603.20953v1) — accessed 2026-07-23
- [github.com/aporthq/aport-spec](https://github.com/aporthq/aport-spec) — README, LICENSE (MIT), `oap/delegation.md`, `conformance/`, commit history — accessed 2026-07-23
- [github.com/aporthq (org repo list via GitHub API)](https://github.com/aporthq) — liveness/stars/issues — accessed 2026-07-23
- [github.com/aporthq/aport-agent-guardrails](https://github.com/aporthq/aport-agent-guardrails) — file tree (no delegation impl), npm registry metadata for `@aporthq/aport-agent-guardrails` — accessed 2026-07-23
- [aport.io/spec](https://aport.io/spec/) — spec portal — accessed 2026-07-23
- Ambiguity check: [agent-passport.org (APS)](https://agent-passport.org/), [Cubitrek Agent Passport](https://cubitrek.com/agent-passport) — distinct projects — accessed 2026-07-23
