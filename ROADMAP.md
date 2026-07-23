# Roadmap

DelegationBench is an early research project. This roadmap states the work
needed to turn a reproducible synthetic testbed into a benchmark that can support
real agent-system evaluation. It is directional rather than a promise of dates.

## Current baseline — v0.1

- Deterministic runner and authorization oracle.
- 15 attack scenarios and 10 benign lookalikes.
- Tool-boundary delegation-envelope defense and authority-aware fuzzer.
- JSON and terminal reports.
- Initial ROMA and LangGraph adapter research.

## Next

### Harden the security model

- Derive security-relevant facts from trusted trace structure instead of
  accepting event claims.
- Expand principal-continuity, temporal-attenuation, replay, and malformed-trace
  coverage.
- Replace the demonstration HMAC mode with an asymmetric signed-envelope
  reference design.

### Validate real integrations

- Capture and normalize traces from real multi-agent framework runs.
- Publish an adapter contract with conformance fixtures.
- Demonstrate at least one end-to-end framework integration without weakening
  the deterministic oracle.

### Strengthen benchmark evidence

- Expand attack/benign pairs from independently reviewed threat cases.
- Version the corpus and publish reproducible benchmark reports.
- Document coverage, limitations, and false-positive/false-negative analysis.

### Improve distribution

- Publish signed Python packages and release artifacts.
- Add stable schema documentation and migration guidance.
- Provide a minimal CI integration recipe for downstream agent projects.

## Contributing

The most useful contributions are new attack scenarios with benign twins,
framework trace fixtures, and reproducible oracle or defense findings. See
[CONTRIBUTING.md](CONTRIBUTING.md) and open an
[Idea discussion](https://github.com/sergeyizmailov/delegationbench/discussions/categories/ideas)
before starting a large change.
