# Governance

DelegationBench is a security testbed: trust in its corpus and oracle is the
product. This document describes how changes are reviewed and released.

## Roles

- **Maintainer** — `sergeyizmailov`. Owns the repository, reviews and merges
  pull requests, cuts releases, and holds the security contact.
- **Contributors** — anyone opening issues or pull requests. Significant
  scenario contributions are credited in the changelog.

Decision making is by the maintainer, in the open (issues/PRs). As the
contributor base grows, this document will be extended with a reviewer
rotation and lazy-consensus rules.

## Scenario review

The corpus is the security claim, so scenarios get the strictest review:

1. Every attack scenario must have a benign lookalike (existing or new) so
   defenses cannot score by blocking everything.
2. Every scenario must declare a complete `expect` block — verdict, violation
   kinds, unauthorized actions, and (for benign) outcome assertions — verified
   against the *actual* oracle output, not written by hand.
3. Expectations match exactly by default; `allow_additional: true` needs a
   justification in the PR.
4. CI must pass: unit tests, the full corpus in all three defense modes
   (`none`, `envelope`, `envelope-sign`), the SARIF schema gate, the real
   LangGraph integration gate, and the fuzzing gate.
5. New violation behavior must map to a class in [THREAT_MODEL.md](THREAT_MODEL.md)
   (V1–V7). If it does not fit, the threat model is extended first, in the
   same PR.

## Release cadence and versioning

- Semantic versioning: patch for fixes, minor for backward-compatible
  features (new scenarios, new outputs), major for schema or CLI contract
  breaks.
- Releases are cut from tags on `main` after a green CI run; there is no
  fixed schedule — security fixes ship as soon as they are reviewed.
- Every release attaches the wheel, sdist, SPDX SBOM, GitHub artifact
  attestation, and SLSA provenance; see [docs/releasing.md](docs/releasing.md).

## Compatibility policy

Stable within a major version:

- the scenario schema (`schema: 1`) — additive fields only;
- the CLI commands, flags, and exit codes (0 = match, 1 = mismatch,
  2 = usage error);
- the report formats (JUnit, SARIF, versioned JSON benchmark report);
- the trace event model consumed by the adapters and
  `delegationbench validate-adapter`.

Experimental (may change with notice in the changelog): the `fuzz` campaign
output layout and the framework adapter APIs while framework majors are
gated (`langgraph>=1,<2`).

## Security handling

Security issues in DelegationBench itself (oracle misjudgment, defense
bypass, trace-integrity flaws) follow [SECURITY.md](SECURITY.md): private
report, acknowledgement within 3 business days, coordinated fix and
disclosure within 90 days. The reference defense is a benchmark artifact,
not a production authorization gateway — findings against it are still
taken seriously because users copy it.

## Code review

All changes land through pull requests with required CI checks (unit tests
on Python 3.10–3.13, package build, LangGraph integration, CodeQL, and the
ClusterFuzzLite fuzzing gate). Independent review is required from anyone
who is not the PR author; the maintainer's own PRs are exempt until the
project has a second active reviewer — external reviewers are explicitly
welcome and listed in [CODEOWNERS](.github/CODEOWNERS) as they join.
