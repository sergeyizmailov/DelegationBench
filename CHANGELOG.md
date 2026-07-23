# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added tokenless PyPI Trusted Publishing automation and a release runbook.

### Fixed

- Pinned the OpenSSF Scorecard workflow to a valid release commit and granted
  the analysis job the minimum repository-read permission it requires.

## [0.4.4] - 2026-07-23

### Added

- Bundled the complete 75-scenario corpus in wheel and source distributions so
  the documented quickstart works from any PyPI installation.
- Added OWASP Agentic Top 10, CWE, and MITRE ATLAS mappings to SARIF findings.
- Added OpenSSF Scorecard reporting and a repository badge.
- Added tagged-release automation for SLSA provenance attestations and an SPDX
  SBOM.
- Added ready-to-send external validation outreach templates.

### Fixed

- **Scenario corpus ships inside the package.** The 75 scenarios moved from
  the repo-root `scenarios/` into `src/delegationbench/scenarios/` and are
  included as package data, so the documented quickstart
  `delegationbench run scenarios/` works from a PyPI wheel or sdist install,
  not only from a repo checkout. CLI path resolution is unchanged for real
  filesystem paths; a nonexistent `scenarios/...` argument (directory or
  single file) falls back to the bundled corpus via `importlib.resources`
  and prints a one-line note on stderr. `delegationbench fuzz` resolves
  seed paths the same way. Tests locate the corpus through
  `delegationbench.corpus.corpus_path()` instead of a hardcoded repo-root
  path, so they also pass from an sdist.

## [0.4.3] - 2026-07-23

### Fixed

- Use an absolute GitHub asset URL so the project hero renders correctly on
  PyPI and other package-index mirrors.
- Add a direct PyPI version badge to the repository README.

## [0.4.2] - 2026-07-23

### Changed

- Published the package distribution through PyPI.
- Updated installation and CI examples to the current release.
- Kept public release documentation focused on the project and its technical
  evidence.

## [0.4.1] - 2026-07-23

Hardening release driven by a final adversarial review. No scenario verdict
changed.

### Security

- **Renewal widening closed** — re-delegating an existing task id now compares
  the new scope/expiry against the task's *prior* effective authority in both
  the oracle (V1) and `EnvelopeGuard` (blocked). Previously a same-task
  re-delegation with a wider (still parent-bounded) scope silently expanded
  authority.
- **`EnvelopeGuard` keeps its own authority map** — delegations under parents
  the guard never approved are rejected (V5); child envelopes whose carried
  fields contradict guard-derived authority/depth/expiry are rejected even
  without signing; tool calls are judged against derived authority and the
  calling agent is checked against the task's delegated agent.
- **`unauthorized_executed` is no longer content-gameable** — refusal detection
  parses the result payload structurally and matches results per call instead
  of pooling; unprovable refusals count conservatively as executed.
- **Errored scenarios surface in CI reports** — JUnit emits `<error>` testcases
  and SARIF emits `scenario-load-error` results instead of silently dropping
  broken files.
- Default HMAC signing key now emits a runtime warning.

### Fixed

- Loader: optional capture groups referenced by templates, non-mapping YAML
  nodes, NaN/Inf/bool in numeric fields, and root `task.read` capability/grant
  mismatches are rejected at load with `ScenarioError` (was: mid-run crashes).
- Tools: non-positive payment amounts rejected; mid-run `payment_limit`
  tampering to a non-integer degrades gracefully; generated email ids no longer
  overwrite seeded ones.
- Adapters: empty-string principal inherits (unified across both build_trace
  paths); `action_map` values validated; `handoff_prefixes=()` respected.
- CLI: broken-pipe exits cleanly; `--benchmark-report` written on all error
  paths; `fuzz --fail-on-bypass` flag for CI gating; fuzzer dedups no-op
  mutants; trace event cap off-by-one; V7 added to the scenario issue template.
- Nonce replay model aligned between oracle and guard ((principal, nonce),
  empty nonces exempt).

## [0.4.0] - 2026-07-23

### Added

- Expanded the deterministic corpus to 75 scenarios: 38 attacks and 37 benign
  twins spanning V1-V7, with paired coverage across document, email, payment,
  configuration, expiry, replay, depth, origin, result, and principal surfaces.
- Added corpus release gates and a versioned scenario-coverage matrix.
- Added a real open-weight LLM + LangGraph benchmark harness with repeated
  attack/benign trials, per-run traces, explicit failure accounting, redacted
  endpoint metadata, and reproducibility fields.
- Added a reproducibility protocol for reviewed real-model reports.

### Changed

- Updated README installation, output-format, CI, and real-LLM demo guidance
  for the v0.4.0 baseline.
- Migrated the public LangGraph adapter example from deprecated
  `create_react_agent` to `langchain.agents.create_agent`.
- Made the composite GitHub Action attempt both JUnit and SARIF generation
  before enforcing a failed benchmark result, preserving diagnostics on
  regressions.
- Updated citation/package metadata, the reproducible benchmark protocol, and
  the current product roadmap.

## [0.3.0] - 2026-07-23

Hardening release driven by a second external security review.

### Security

- **Principal fails closed** — an event with a missing/empty principal under a
  principal-bearing root grant is now a violation (V5 origin loss), not clean.
- **Reference defense enforces V7** — `EnvelopeGuard` binds the root principal
  and blocks delegations/tool calls under a substituted principal, even when
  every requested action is in-grant (new scenario attack-016 proves the
  V7-only path; attack-011 previously relied on V1/V2 masking).
- **Trace topology validation** — multiple root delegations, duplicate task
  ids (re-binding to a different parent/agent; identical re-issue with a fresh
  nonce remains legitimate renewal), and tool calls by an agent other than the
  task's delegatee are judged V5 trace-integrity violations.
- **Adapters propagate principal** — both the LangGraph and ROMA paths stamp
  `Event.principal` on every event, so V7 works through real framework traces.
- **Unpaired adapter tool results** are surfaced as synthetic uncorrelated
  tool calls (V5-judgeable) instead of being silently dropped.

### Added

- **CI report formats** — `--format junit` / `--format sarif`, `--output`,
  and `--benchmark-report` (versioned JSON bundle) for pipeline integration.
- **Composite GitHub Action** (`action.yml`) — run DelegationBench in your own
  CI with JUnit/SARIF artifacts; see `docs/ci-integration.md`.
- **Exact expectation matching** — `expect.violation_kinds` and
  `unauthorized_actions` must match the oracle exactly; `expect.allow_additional`
  opts back into subset semantics. Corpus migrated (attack-008's expect made
  exact — it was hiding an unauthorized `payment.prepare`).
- **Benign scenarios require `expect.outcomes`** — a benign run without
  declared outcomes counts as *incomplete*, never as success.
- **Attempts vs executed** — metrics now distinguish unauthorized action
  *attempts* from *executed* side effects (`unauthorized_calls` kept as alias).
- **Fuzzer robustness** — static dangling-resource validation rejects broken
  mutants pre-run; no campaign abort path remains (15-seed campaign: zero
  aborts, zero errors, zero defense bypasses).
- **LangGraph integration migrated** to `langchain.agents.create_agent`
  (`create_react_agent` deprecated); integration tests run warning-free and
  the `integration` job is a required branch-protection check.

### Fixed

- Cyclic delegation chains raise a clean `EngineError` (CLI exit 2) instead of
  `RecursionError`; direct self-delegation is rejected at scenario load.

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

[Unreleased]: https://github.com/sergeyizmailov/delegationbench/compare/v0.4.4...HEAD
[0.4.4]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.4.4
[0.4.3]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.4.3
[0.4.2]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.4.2
[0.4.1]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.4.1
[0.4.0]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.4.0
[0.3.0]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.3.0
[0.2.0]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.2.0
[0.1.0]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.1.0
