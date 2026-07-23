# ScopeGate (scopegate-runtime) — Competitive Audit

- **Project:** ScopeGate Runtime (`raceksd-source/scopegate-runtime`)
- **Canonical repo:** https://github.com/raceksd-source/scopegate-runtime
- **Paper:** https://arxiv.org/abs/2606.28679 — *Confused-Deputy Failures in LLM Agent Frameworks* (David Mellafe Zuvic, v1 2026-06-27)
- **Access/research date:** 2026-07-23
- **Name ambiguity:** There are two distinct projects named ScopeGate. This audit covers **scopegate-runtime**, the paper-linked deterministic authorization gate — the most likely intended match for a security-benchmark comparison. The alternative, [`alifanov/scopegate`](https://github.com/alifanov/scopegate) (scopegate.dev), is an MCP permission gateway / access-proxy SaaS-style dashboard (Next.js, MIT, 15 stars, actively pushed 2026-07-21); it also has no delegation-chain or benchmark functionality.

## 1. What it is

ScopeGate Runtime is a small Python SDK (PDP/PEP middleware) that sits between an LLM's emitted tool call and the side-effecting tool, and deterministically decides — fail-closed, default-deny — whether the call with concrete argument values is authorized by a static policy (argument allowlists, money ceilings, idempotency keys). It is the companion artifact to an arXiv paper auditing LangChain/LangGraph, LlamaIndex, and the Stripe Agent Toolkit, showing none re-authorize per-call argument values by default (the confused-deputy gap). It is a **deployable runtime control**, not a benchmark or testbed.

## 2. Multi-agent?

**No.** All scenarios are a single agent emitting tool calls (e.g., a WhatsApp payment-agent replica). There is no agent-to-agent delegation anywhere in the repo or paper.

## 3. Differential privileges?

**Partial.** Policies are per-tool and per-argument-value (`ToolPolicy` with allowlists/ceilings), and each gate instance enforces one static policy — so you could run different gates for different agents, but there is no model of multiple principals with differing authority levels interacting in one scenario, and no notion of one principal being "higher authority" than another.

## 4. Origin tracking?

**No.** The policy is static configuration; there is no representation of an originating user, their intent, or their identity. The only context passed is per-call metadata (e.g., an idempotency key). Nothing propagates a user identity through calls.

## 5. Chain-wide authority check?

**No.** The check is explicitly per-call and local: *"Is this call, with these argument values, authorized by policy?"* (five-stage invariant: scope → authz → money → idempotency → pass). There is no chain, no delegation token, no cross-hop authority comparison. It is precisely the "per-tool-call check" end of the spectrum DelegationBench targets.

## 6. Attack generation?

**No.** The adversarial coverage is a hand-written static suite: 48 bypass vectors in `tests/test_bypass.py` (case/whitespace/zero-width/homoglyph/null-byte/type-confusion/tool-name-mutation/money-edge/idempotency). The paper mentions a "40-iteration adaptive run" (0/29 unauthorized attempts) against the gate, but no generator/mutator ships in the repo — the README lists "the automated adaptive-attacker ceiling" and "expand to 1000+ vectors" as **open items**.

## 7. Exploit minimization?

**No.** No trace minimization or reproducer-shortening anywhere.

## 8. Regression tests?

**Partial.** The bypass suite doubles as a hand-curated regression suite — a real fail-open found by it (NaN as a money amount passing the naive `> ceiling` check) was fixed and enshrined as a test. But there is no mechanism that automatically emits standalone regression tests from findings in *user* systems.

## 9. ROMA integration?

**No.** No mention of ROMA / sentient-agi anywhere in repo, paper, or README. Integrations shipped: LangChain PoC, LlamaIndex PoC, benign control.

## 10. Liveness

- **Stars:** 0 · **Forks:** 0 · **Open issues:** 0
- **Created:** 2026-06-26 · **Last push:** 2026-06-26 (2 commits, both on the same day)
- **Commit cadence:** one-day artifact drop accompanying the paper; no activity in the ~4 weeks since (as of 2026-07-23)
- **Releases:** none (no GitHub releases, no tags; version 0.1.1 stated in README/pyproject only)
- Verdict: effectively dormant single-author research artifact.

## 11. License

**Apache-2.0.** Full Apache 2.0 text in `LICENSE` (Copyright 2026 David Mellafe Zuvic); README also states "Apache-2.0". GitHub's API reports `NOASSERTION` because the license header is non-standardly worded ("should be included as the canonical LICENSE on publication"), but the text is Apache-2.0.

## 12. Overlap verdict

**NONE (adjacent mitigation, not a testbed).** ScopeGate shares DelegationBench's *philosophy* — deterministic, fail-closed, non-LLM judgment of whether an action is authorized — and ships a static adversarial conformance suite. But it is a runtime defense control for a single agent's tool calls, not a benchmark: no multi-agent delegation, no differential privilege model across principals, no origin/intent tracking, no chain-wide authority semantics, no attack generation (roadmap only), no exploit minimization, no regression-test emission. It does not detect privilege escalation across delegation chains — the per-call gate it provides is exactly the class of point control whose chain-level blind spots DelegationBench is designed to expose. If anything, ScopeGate-style gates are candidate *targets/baselines* for DelegationBench, not competitors.

## Key quotes/evidence

- "Deterministic, fail-closed, per-call authorization for AI agent tool calls. The LLM is an untrusted parser." — README
- "Is this call, with these argument values, authorized by policy? Everything not explicitly allowed is denied." — README (decision invariant: scope → authz → money → idempotency → pass)
- "the popular agent frameworks … ship capability gating (which tools exist) but not per-call authorization … the textbook confused-deputy gap" — README
- "Honest open items: expand to 1000+ vectors, sidecar/gateway deployments, the automated adaptive-attacker ceiling, an independent (third-party) red-team." — README
- "the tested control reports 0/48 static bypasses, 0/29 unauthorized attempts (40-iteration adaptive run), 0/10 benign false-denies" — arXiv abstract
- `tests/test_bypass.py` header: "This suite throws a broad set of evasion vectors at the gate and asserts the security invariant holds" — 48 hand-written static vectors; the suite "found and fixed a real fail-open — NaN as a money amount"

## Sources

- https://github.com/raceksd-source/scopegate-runtime — README, tree, tests (accessed 2026-07-23)
- https://arxiv.org/abs/2606.28679 — abstract (accessed 2026-07-23)
- https://arxiv.org/html/2606.28679v1 — full text (accessed 2026-07-23)
- https://api.github.com/repos/raceksd-source/scopegate-runtime (+ /commits, /releases, /tags) — liveness metadata (accessed 2026-07-23)
- https://raw.githubusercontent.com/raceksd-source/scopegate-runtime/main/LICENSE and /tests/test_bypass.py (accessed 2026-07-23)
- https://github.com/alifanov/scopegate and https://scopegate.dev/ — alternative same-name project (accessed 2026-07-23)
