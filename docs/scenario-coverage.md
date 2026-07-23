# Scenario coverage

DelegationBench contains **75 executable scenarios**: 38 attacks and 37 benign
cases. Every YAML file is run in the no-defense, envelope, and signed-envelope
test matrix.

The v0.4 candidate adds 22 explicit attack/benign pairs. Each pair keeps the
workflow constant and changes one authorization condition, reducing the chance
that a detector passes by recognizing attack wording instead of the violated
invariant.

| Attack | Benign twin | Invariant | Surface |
|---|---|---|---|
| attack-017 | benign-016 | V1/V2 | document write |
| attack-018 | benign-017 | V1/V2 | email send |
| attack-019 | benign-018 | V1/V2 | payment execute |
| attack-020 | benign-019 | V1/V2 | configuration update |
| attack-021 | benign-020 | V3 | two-hop support routing |
| attack-022 | benign-021 | V3 | three-hop procurement routing |
| attack-023 | benign-022 | V3 | four-hop research routing |
| attack-024 | benign-023 | V4 | document-envelope replay |
| attack-025 | benign-024 | V4 | mailbox-envelope replay |
| attack-026 | benign-025 | V4 | document expiry |
| attack-027 | benign-026 | V4 | mailbox expiry |
| attack-028 | benign-027 | V5 | detached document write |
| attack-029 | benign-028 | V5 | detached email send |
| attack-030 | benign-029 | V5 | detached configuration update |
| attack-031 | benign-030 | V6/V2 | result-driven document write |
| attack-032 | benign-031 | V6/V2 | result-driven email send |
| attack-033 | benign-032 | V6/V2 | result-driven configuration update |
| attack-034 | benign-033 | V7 | document principal |
| attack-035 | benign-034 | V7 | email principal |
| attack-036 | benign-035 | V7 | payment principal |
| attack-037 | benign-036 | V7 | configuration principal |
| attack-038 | benign-037 | V7 | mailbox principal |

The original 31 scenarios remain as independently structured regression cases,
including credential forwarding, supervisor impersonation, orchestrator
bypass, sibling contamination, and scope attenuation.

## Review policy

A scenario is release-ready only when:

1. it loads under the strict schema;
2. its exact violation-kind, unauthorized-action, and outcome contract matches;
3. its benign twin completes the intended task without a violation;
4. both reference defenses contain the attack without overblocking the twin;
5. a maintainer reviews the scenario text and confirms that the pair differs by
   the intended security boundary.

Automated checks enforce items 1–4. Item 5 must be recorded in the release pull
request; passing tests alone is not described as independent review.
