# Roadmap

DelegationBench is an early open-source security project. This roadmap
separates what is reproducible today from the evidence still required before a
Sentient Foundation application.

## Current baseline — v0.4.0 release candidate

- Deterministic runner, authorization oracle, delegation-envelope reference
  defense, and authority-aware fuzzer.
- 75 scenarios: 38 attacks and 37 benign twins covering V1–V7.
- Terminal, JSON, JUnit, SARIF, and versioned benchmark reports.
- Composite GitHub Action and one-command CI integration.
- LangGraph adapter with real compiled-graph integration tests, explicit
  principal propagation, custom handoffs, task scope, and parallel-delegation
  correlation.
- Experimental clean-room ROMA adapter; a real ROMA run remains blocked on
  licensing clarification and maintainer validation.
- Real open-weight LLM + LangGraph demo harness. Repeated multi-model results
  have not yet been accepted as a public benchmark.

## Pre-submission gates

The project should not claim grant readiness until all of these gates close:

1. **Real-model evidence** — run the public LangGraph demo against at least two
   open-weight models, with repeated attack and benign trials, fixed
   configurations, full traces, and published versioned reports.
2. **External validation** — collect feedback from 3–5 relevant framework
   developers or security engineers; at least one must confirm they would test
   or use DelegationBench in a workflow or CI.
3. **Corpus review** — record maintainer editorial review for the 22 new
   attack/benign pairs; automated gates already enforce execution, containment,
   benign completion, and V1–V7 coverage.
4. **Application decisions** — approve the requested budget, duration, and
   applicant details. No agent-generated funding figure is authoritative.
5. **Submission assets** — publish a short demo, benchmark summary, external
   validation record, milestone table, and final application narrative.

The public supporting brief and 90-second demo recording script are already
prepared; the final recording should use the tagged release and must not claim
pending model or external-validation evidence.

See [docs/grant-readiness.md](docs/grant-readiness.md) for the evidence matrix
and exact acceptance criteria.

## Proposed delivery sequence

### Gate A — Evidence and validation

- Publish results for two open-weight models with at least 10 attack and 10
  benign trials per model/configuration.
- Record model identifiers, serving versions, temperature, prompts, hardware,
  run counts, failures, latency, and full DelegationBench traces.
- Complete 3–5 external validation conversations using the
  [validation kit](docs/validation-kit.md).

### Gate B — Corpus and integration depth

- Review and maintain the 75-scenario paired corpus; expand further where
  external framework feedback identifies missing surfaces.
- Publish a V1–V7 coverage matrix and review checklist.
- Add LangGraph conformance fixtures for custom handoffs, explicit scopes, and
  parallel fan-out.
- Run the ROMA adapter only after licensing and API assumptions are confirmed.

### Gate C — Grant packet

- Approve budget and duration.
- Freeze benchmark reports against a tagged release.
- Publish the demo and concise technical article.
- Submit with links to the repository, release, reports, validation evidence,
  threat model, competitive research, and measurable post-grant milestones.

## Longer-term direction

- Stable scenario and trace schemas with migration guidance.
- Additional framework adapters selected by demonstrated user demand.
- Asymmetric signed delegation envelopes as a production-oriented reference
  design.
- Community scenario review and cross-framework regression sharing.
- PyPI trusted publishing and signed/provenanced release artifacts.

## Contributing

The most useful contributions are new attack scenarios with benign twins,
framework trace fixtures, and reproducible oracle or defense findings. See
[CONTRIBUTING.md](CONTRIBUTING.md) and open an
[Idea discussion](https://github.com/sergeyizmailov/DelegationBench/discussions/categories/ideas)
before starting a large change.
