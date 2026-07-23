# Sentient Grant Application Draft

This is a working draft for the **grant** track, based on the public form
verified on 2026-07-23. Bracketed fields require the applicant's own answer.
Do not submit this text until the evidence links and funding decision are
complete.

## Who are you?

- **Email:** `[Applicant email]`
- **Primary role:** `[Researcher / Engineer-Builder / Founder / other]`
- **Based in:** `[City, country]`

## What problem are you solving, and why now?

Multi-agent systems increasingly delegate one user request across agents that
have different tools and permissions. Existing per-agent checks can still
allow a low-authority agent to induce a more privileged agent to act outside
the user's original authorization. This confused-deputy failure becomes more
important as agents gain access to files, browsers, email, infrastructure, and
payments. Teams need a shared executable test now, before unsafe handoffs
become production incidents.

DelegationBench makes this failure reproducible. It records delegation and tool
events, reconstructs effective authority across the task graph, and uses a
deterministic oracle—not another LLM—to identify authority expansion,
principal substitution, replay, origin loss, and related failures.

## Who does this help?

The primary users are maintainers of multi-agent frameworks, engineering teams
building agent workflows, AI security engineers, red teams, and researchers.
The immediate focus is teams using LangGraph-style handoffs and recursively
delegating systems such as ROMA. The downstream beneficiaries are users whose
agents can reach sensitive tools or data and who need the original
authorization to remain intact across every handoff.

## In one line, what are you building?

> Open security tests that catch unsafe handoffs between AI agents.

This line is under the form's 80-character limit.

## Who is building this, and why is your team the right one?

`[Applicant name and one specific, verifiable reason they are suited to build
this. Include relevant shipped work, security/agent experience, or direct
motivation. Do not use generic AI-generated praise.]`

## What is open, and what gets worse if it closes?

The scenario format, attack and benign corpus, adapters, fuzzer, deterministic
oracle, reference defense, CI integration, and benchmark reports are Apache
2.0-licensed and publicly inspectable. Openness is functional, not decorative:
a security failure found in one framework can become a regression test that
another team can reproduce and extend.

If DelegationBench became closed, framework maintainers and smaller teams would
lose a shared way to inspect the judgment logic, verify benchmark claims,
contribute new attacks, and carry the same regression across frameworks.
Agent-handoff security would return to private one-off tests that do not
compound into a common defense.

## Demo or trial links

- Repository: <https://github.com/sergeyizmailov/DelegationBench>
- Current release candidate: <https://github.com/sergeyizmailov/DelegationBench/releases/tag/v0.4.0>
- Threat model: <https://github.com/sergeyizmailov/DelegationBench/blob/main/THREAT_MODEL.md>
- CI integration: <https://github.com/sergeyizmailov/DelegationBench/blob/main/docs/ci-integration.md>
- `[Add reviewed open-weight benchmark report links]`
- `[Add short demo video link]`

## Track

**Grant** — no equity. Final selection remains the applicant's decision.

## How much funding are you asking for?

`[Choose one after reviewing scope: USD 10k / 25k / 50k / >50k]`

No amount is approved in this repository.

## What would the grant unlock?

The grant would turn a security-hardened deterministic testbed into externally
validated shared infrastructure:

1. externally review and maintain the 75-scenario attack/benign corpus with
   explicit V1–V7 coverage;
2. publish repeated real-model benchmarks for multiple open-weight models,
   including attack success, false positives, benign task success, failures,
   configurations, and full traces;
3. validate the integration with framework developers and security engineers;
4. stabilize LangGraph conformance fixtures and validate ROMA only after its
   licensing and runtime assumptions are confirmed;
5. publish stable schemas, documentation, demo material, and reproducible CI
   workflows so other teams can adopt and contribute tests.

`[After choosing the funding band and duration, map each item to a dated
milestone and budget allocation.]`

## Supporting document

Required by the form. Prepare one concise PDF or deck containing:

1. problem and concrete unsafe-handoff example;
2. deterministic authority invariant;
3. working architecture and trace;
4. v0.4.0 evidence and CI integration;
5. real-model benchmark results;
6. external validation;
7. competitive distinction;
8. approved milestones, duration, and budget;
9. ecosystem impact and open-source argument.

Do not finalize this document before real-model and external-validation
evidence exists.

## How did you hear about the program?

`[Conference / X / GitHub-HuggingFace / word of mouth / Sentient team member /
other — applicant answer]`
