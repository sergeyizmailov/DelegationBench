# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/sergeyizmailov/delegationbench/releases/tag/v0.1.0
