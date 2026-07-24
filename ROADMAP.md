# Roadmap

DelegationBench is an early open-source security project. The roadmap separates
the reproducible baseline available today from the validation and integration
work needed for a stable release.

## Current baseline — v0.4.5

- Deterministic runner, authorization oracle, delegation-envelope reference
  defense, and authority-aware fuzzer.
- 75 scenarios: 38 attacks and 37 benign twins covering V1–V7.
- The reviewed corpus ships in the PyPI wheel and source distribution.
- Terminal, JSON, JUnit, SARIF, and versioned benchmark reports.
- Composite GitHub Action and one-command CI integration.
- Schema-validated SARIF uploads to GitHub code scanning; findings map to
  OWASP Agentic Top 10, CWE, and MITRE ATLAS.
- OpenSSF Scorecard, release provenance attestations, and SPDX SBOM generation.
- LangGraph adapter with compiled-graph integration tests, explicit principal
  propagation, custom handoffs, task scope, and parallel-delegation
  correlation.
- Experimental clean-room ROMA adapter.
- Real open-weight LLM and LangGraph demo harness for repeated trials.

## Near term

### Reproducible model evidence

- Publish reviewed results for at least two open-weight models.
- Run repeated attack and benign trials with fixed configurations.
- Record model revisions, serving versions, prompts, hardware, failures,
  aggregate metrics, and full traces.
- Follow the [benchmark protocol](docs/benchmark-protocol.md).

### External validation

- Collect reproducible feedback from framework developers and security
  engineers.
- Validate the one-command CI workflow in downstream repositories.
- Turn integration obstacles into tracked issues and regression fixtures.

### Corpus and integration depth

- Maintain paired attack and benign coverage across V1–V7.
- Expand the corpus when framework feedback identifies missing security
  boundaries.
- Add LangGraph conformance fixtures for custom handoffs, explicit scopes, and
  parallel fan-out.
- Run the ROMA adapter after licensing and API assumptions are confirmed.

## Stable release

- Complete the one-time PyPI Trusted Publisher binding for the tokenless
  release workflow.
- Stabilize the scenario and trace schemas with migration guidance.
- Maintain provenance-attested release artifacts and versioned SBOMs.
- Document supported framework versions and adapter compatibility.
- Tag v1.0 after downstream reproduction and corpus review.

## Longer-term direction

- Additional framework adapters selected by demonstrated user demand.
- Asymmetric signed delegation envelopes as a production-oriented reference
  design.
- Community scenario review and cross-framework regression sharing.
- Broader authority surfaces, including browser sessions, wallets, cloud APIs,
  and MCP tools.

## Contributing

The most useful contributions are new attack scenarios with benign twins,
framework trace fixtures, and reproducible oracle or defense findings. See
[CONTRIBUTING.md](CONTRIBUTING.md) and open an
[Idea discussion](https://github.com/sergeyizmailov/DelegationBench/discussions/categories/ideas)
before starting a large change.
