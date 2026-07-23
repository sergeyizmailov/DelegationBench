# Security Policy

## Reporting a vulnerability

Please report security issues through GitHub's private vulnerability reporting:

**Security → Advisories → Report a vulnerability**

(<https://github.com/sergeyizmailov/delegationbench/security/advisories/new>)

Do not open a public issue for security problems.

- **Acknowledgement:** within 3 business days.
- **Triage & fix:** we aim to coordinate a fix and disclosure within 90 days.

## Scope

In scope:

- Bugs in the oracle that misjudge authority (false negatives on attack-shaped
  traces, false positives on benign traces).
- Circumventions of the reference defense (`EnvelopeGuard`) — a scenario that
  executes an unauthorized action with `--defense envelope` active is a finding;
  the fuzzer (`delegationbench fuzz --defense envelope`) exists to hunt these.
- Trace-integrity issues (forged or tampered envelopes accepted by the guard).

Out of scope:

- The mock tools themselves (they are intentionally simplified).
- Attack content in `scenarios/attacks/` — malicious instructions are the
  fixture, not a vulnerability.
- Findings requiring real LLM/framework integrations that are not part of the
  deterministic core (report those as regular issues).

## A note on what this project is

DelegationBench is an offensive-security *testbed*: it ships attack scenarios on
purpose. Running it executes mock tools only — no real payments, emails, or
filesystem changes outside its sandbox stores.
