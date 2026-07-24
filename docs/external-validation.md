# External validation

DelegationBench has three attributable public validation reports from
developers and security practitioners. The reports include commands,
environments, observed results, limitations, and approval for public
attribution.

| Report | Version tested | Evidence | Workflow / CI assessment |
|---|---|---|---|
| [Issue #20](https://github.com/sergeyizmailov/DelegationBench/issues/20) by [`@itsmilaverden-droid`](https://github.com/itsmilaverden-droid) | v0.4.4 | Clean PyPI install, full corpus and tests, report formats, plus a [separate downstream CI repository](https://github.com/itsmilaverden-droid/delegationbench-ci-test). The CI run found three defects that were fixed in v0.4.5. | Conditional in the reviewer's original report. |
| [Issue #21](https://github.com/sergeyizmailov/DelegationBench/issues/21) by [`@wodastoks-source`](https://github.com/wodastoks-source) | v0.4.4 | Clean PyPI install, full corpus and tests, LangGraph integration, reports, and paired-scenario review. | Conditional pending custom scenarios and live-system adapter validation. |
| [Issue #24](https://github.com/sergeyizmailov/DelegationBench/issues/24) by [`@ofareref`](https://github.com/ofareref) | v0.4.5 | Clean PyPI install, 302 tests, all defense modes including fail-closed signing, report formats, and a tampered-expectation negative test. | **Yes** for the documented CI-gate use case. |

These are independent user-submitted reports, not formal audits. They validate
installation, reproducibility, the deterministic corpus, outputs, and the
documented CI workflow. They do not establish production security for every
agent topology. Adopters still need scenarios and adapter mappings that reflect
their own agents, tools, principals, and authority boundaries.

The project does not require positive feedback. Reviewers are asked to report
failures and limitations; the defects reported in issue #20 became regression
tests and were released in v0.4.5.
