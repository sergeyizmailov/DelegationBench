# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-23

Hardening release driven by an external security review of 0.1.0.

### Security

- **Oracle no longer trusts reported structure** — delegation depth is derived
  from the parent-task graph (contradicting reported depth is itself flagged),
  effective expiry is the minimum along the delegation path, and temporal
  attenuation is enforced (a child envelope may not outlive its parent).
- **Principal tracking** — every trace event is stamped with the principal of
  its authorizing envelope; a mismatch with the root grant is a new violation
  class **V7 (principal substitution)**.
- **Defense chokepoint closed** — the root task's initial resource reads now go
  through `EnvelopeGuard` like every other tool call.
- **ROMA adapter attribution** — concurrent sibling tasks are correlated via
  `contextvars` instead of a single global stack; ambiguous attributions fall
  back to `uncorrelated` (V5-detectable) instead of risking a wrong one.
- **ROMA adapter ordering** — captured events are topologically reordered
  (delegations before their tasks' tool calls), so post-hoc DAG registration no
  longer produces false origin-loss verdicts.

### Added

- **Real LangGraph integration test** — a compiled two-agent graph with a real
  handoff is executed against the adapter (no API keys, fake chat model);
  runs in CI as a dedicated `integration` job.
- **LangGraph action mapping** — `DelegationBenchCallback(action_map=...)` maps
  framework tool names (`read_doc`) to canonical grant actions (`docs.read`);
  unmapped names pass through and are judged on their raw name.
- **Utility assertions** — `expect.outcomes` verifies the task actually
  completed (payments executed, drafts created, config unchanged, …).
  **Benign Task Success Rate now requires zero blocks AND outcomes met** —
  an agent that does nothing no longer scores 100%.
- **Corpus: 30 scenarios (15 attack + 15 benign)** — attack-011 rewritten as a
  true two-principal scenario (V7, via the new `as_principal` rule field);
  attack-012's mechanism locked by real `payment_limit` enforcement; new benign
  counterparts for V4 expiry boundary, V4 replay (fresh-nonce renewal), V5
  origin preservation, V6 child-result, and a two-principal lookalike.
- **Extensible action vocabulary** — scenarios may declare custom actions
  (`actions: [crm.contacts.export, ...]`) executed via a generic recording tool.
- **Fuzzer: integrity operators** — `principal_substitution`,
  `untracked_inject`, `identity_renaming`, `envelope_tamper`. Classifier fixed:
  mutants whose payload no longer triggers any agent rule count as `dead`, not
  as oracle divergences. 15-seed campaign (3200+ valid mutants,
  `--defense envelope`): zero defense bypasses.

### Fixed

- `payment.execute` enforces `resources.config.payment_limit` — sibling
  configuration tampering is now technically real, not narrative.
- Fuzzer campaigns no longer crash on mutants that strand content-driven
  resource reads; they are discarded and counted (`errors`).

## [0.1.0] - 2026-07-23

Initial public release.

### Added

- **Core engine** — YAML scenario format (schema v1), scripted-agent runner with
  virtual clock, capability manifests, and full delegation/tool-call traces.
- **Deterministic authorization oracle** — judges six violation classes over the
  trace with no LLM in the loop: V1 authority expansion on handoff, V2 confused
  deputy, V3 depth violation, V4 expired/replayed delegation, V5 origin loss,
  V6 scope widening via child result.
- **Scenario corpus** — 15 attack scenarios (credential forwarding, supervisor
  impersonation, elevated-authority request, orchestrator bypass, scope
  widening, nested depth, malicious child result, malicious document, replay,
  expiry, cross-user contamination, sibling config modification, read→write,
  draft→send, prepare→execute) plus 10 paired benign lookalikes.
- **Reference defense** — delegation-envelope guard enforced at the tool
  boundary (`--defense envelope`), optional HMAC envelope integrity
  (`--defense envelope-sign`). On the shipped corpus: all 15 attacks contained,
  all 10 benign scenarios unaffected.
- **Delegation-aware fuzzer** — nine mutation operators over authority-relevant
  scenario structure, defense-bypass and oracle-divergence classification,
  ddmin-lite exploit minimizer, regression-scenario emission
  (`delegationbench fuzz`).
- **Framework adapters** — ROMA (clean-room, no ROMA code copied) and LangGraph
  (optional `langgraph` extra, callback-based).
- **Reports** — terminal and JSON output; corpus metrics: Unauthorized Action
  Rate, Attack Containment Rate, Benign Task Success Rate.
- **Research documentation** — threat model, competitive landscape audit (10
  projects), ROMA and LangGraph integration audits, feasibility decision record.
- **CI** — GitHub Actions: pytest plus full corpus runs with and without the
  reference defense, on Python 3.10/3.12/3.13.

[0.2.0]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.2.0
[0.1.0]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.1.0
