# Roadmap

DelegationBench is an early open-source security project. The roadmap separates
the reproducible baseline available today from the validation and integration
work needed for a stable release.

## Current baseline — v0.5.0

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
- Reviewed Llama 3.3 70B and Qwen3-Next 80B-A3B result sets: 10 attack
  and 10 benign trials per model, with raw decisions and traces.
- Three attributable external validation reports, including one explicit
  downstream CI-use confirmation.

## Near term

### Broaden model and external evidence

- Add adversarial prompt variants that induce unsafe handoffs often enough to
  exercise the oracle against real-model violations.
- Repeat the current paired task on additional model families and
  self-hosted, revision-pinned weights.
- Convert downstream integration obstacles into tracked issues and regression
  fixtures.
- Grow from three public validations to five, including another live-system
  or downstream CI reproduction.

### Corpus and integration depth

- Maintain paired attack and benign coverage across V1–V7.
- Expand the corpus when framework feedback identifies missing security
  boundaries.
- Add LangGraph conformance fixtures for custom handoffs, explicit scopes, and
  parallel fan-out.
- Run the ROMA adapter after licensing and API assumptions are confirmed.

## Stable release

- Maintain the active tokenless PyPI Trusted Publisher release workflow.
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
