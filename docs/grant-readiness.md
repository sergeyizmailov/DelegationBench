# Sentient Grant Readiness

This document is the source of truth for pre-submission evidence. It prevents
the application from confusing implemented infrastructure with validation that
still depends on real models, external people, or applicant decisions.

Status date: 2026-07-23

Repository baseline: `v0.4.0` release candidate

Primary fit:
[Sentient Unified Security Testbed](https://sentient.foundation/product-requests)
calls for reproducible unsafe-agent-handoff tests that another team can run.

## Readiness matrix

| Requirement | Status | Evidence | Required to close |
|---|---|---|---|
| Real end-to-end LangGraph or ROMA demo with actual LLM decisions, handoffs, tool calls, and DelegationBench evaluation | **Code ready; evidence pending** | `examples/langgraph_real_llm_demo.py`; real compiled-graph integration test | Run the demo reproducibly and publish accepted traces/results |
| External validation from 3–5 relevant developers or security engineers | **Pending (0/3–5)** | `docs/validation-kit.md` | Record 3–5 attributable responses; at least one workflow/CI use signal |
| Repeated open-weight benchmark results | **Pending** | Versioned report writer and real-model harness exist | Publish results for at least two models, repeated attack and benign trials, configurations, failures, and full traces |
| Stable framework integration and authority propagation | **LangGraph implemented; ROMA experimental** | Adapter tests, required CI integration job, custom handoff/scope/parallel APIs | External LangGraph reproduction; ROMA license/API confirmation before a real ROMA claim |
| GitHub Action, JUnit/SARIF, one-command CI, versioned reports | **Complete** | `action.yml`, `docs/ci-integration.md`, CLI output tests | Downstream smoke test is recommended |
| Approximately 75–100 reviewed attack and benign scenarios | **75 executable; maintainer review pending** | 38 attack + 37 benign scenarios; `scenario-coverage.md`; V1–V7 | Record maintainer editorial review of the 22 new pairs in the release PR |
| Grant roadmap, timeline, budget, deliverables, impact | **Partial** | `PROJECT_PLAN.md`, `ROADMAP.md` | Applicant must approve requested amount/duration; convert the approved decision into the final milestone table |
| Sentient-focused README explanation | **Complete** | Opening README paragraph | Keep wording aligned with the final application |

## Acceptance criteria for real-model reports

Each published model/configuration must include:

- exact model identifier and model-weight revision when available;
- inference server and version;
- prompt/harness commit and DelegationBench release;
- temperature, token limit, and any available seed;
- hardware and operating system;
- at least 10 attack and 10 benign trials;
- attack success rate;
- detected authority-violation rate;
- false-positive rate;
- benign task success rate;
- invalid-output, timeout, and execution-error counts;
- per-run trace artifacts, not only aggregate percentages.

Results from a tiny smoke-test model are not automatically publication-grade.
They must be reviewed for task competence and harness validity before inclusion.

## Acceptance criteria for external validation

- 3–5 responses from people who work on agent frameworks, agent applications,
  or security engineering.
- Their name or project, role/relevance, date, and permission level for
  attribution are recorded.
- Feedback includes concrete integration obstacles, not only general praise.
- At least one respondent explicitly says they would test or use
  DelegationBench in a workflow or CI, or provides equivalent behavioral
  evidence by running it.
- No invented testimonials, anonymous composite quotes, or agent-authored
  endorsements.

## Applicant-owned decisions

The following fields must be approved by the applicant before submission:

- requested funding band (`USD 10k`, `25k`, `50k`, or `>50k`);
- grant duration;
- applicant/legal identity and contact details;
- availability and compensation assumptions;
- budget allocation;
- whether external review, compute, travel, or contractor costs are included.

Until approved, the repository must use `TBD — applicant decision` rather than
an agent-generated number.

## Current application form

The [public application](https://form.typeform.com/to/IRj7WaKH) was verified on
2026-07-23. The grant branch asks for:

- email, primary role, and city/country;
- the problem and why now;
- who the project helps;
- an 80-character plain-language project description;
- who is building it and why that person/team is right;
- what is open and who would lose if it became closed;
- demo, GitHub, website, or trial links;
- grant vs investment track;
- requested funding band: `USD 10k`, `25k`, `50k`, or `>50k`;
- what the grant unlocks in the next few months;
- a required supporting-document upload;
- how the applicant heard about the program.

Draft answers and owner-only blanks are tracked in
[grant-application-draft.md](grant-application-draft.md). The form should not be
submitted until the evidence matrix is complete and the applicant has approved
all personal, funding, and timeline fields.

## Submission packet

When every blocking row above is complete, freeze:

1. a tagged DelegationBench release;
2. two or more versioned open-weight benchmark reports;
3. the external validation record;
4. a 90-second demo;
5. the threat model and competitive landscape;
6. a milestone/timeline/budget table approved by the applicant;
7. the final Sentient application narrative.

A public five-page supporting brief is generated from
`scripts/build_grant_brief.py` and stored at
`output/pdf/delegationbench-sentient-technical-brief.pdf`. The reproducible
90-second recording plan is in `docs/demo-video-script.md`. Neither artifact
substitutes for the pending real-model reports or independent validation.

## Non-blocking repository polish

- Upload `.github/assets/social-preview.png` in GitHub repository settings. The
  public repository currently serves GitHub's generated OpenGraph card rather
  than the prepared custom image.
- Configure PyPI Trusted Publishing when the applicant wants a PyPI release.
- Consider signed/provenanced artifacts for the stable release line.
