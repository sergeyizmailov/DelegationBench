# CI integration

DelegationBench can run as a CLI or as a composite GitHub Action. The
oracle is deterministic and does not need an API key.

## One-command CI

```bash
delegationbench run scenarios/ --defense envelope \
  --format junit --output reports/junit.xml \
  --benchmark-report reports/benchmark.json
```

Generate GitHub-compatible SARIF separately:

```bash
delegationbench run scenarios/ --defense envelope \
  --format sarif --output reports/delegationbench.sarif
```

Exit code `0` means every scenario matched its contract. Exit code `1`
means at least one security or benign-task regression. Exit code `2`
means configuration or execution error.

## GitHub Action

```yaml
name: Agent security

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  delegation-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - uses: sergeyizmailov/DelegationBench@v0.4.2
        with:
          scenarios: scenarios
          defense: envelope
          upload-sarif: "true"
```

For an unreleased commit, pin the action to a full commit SHA. Consumers
should pin releases or SHAs rather than `main`.

The action writes:

- `delegationbench-reports/junit.xml`;
- `delegationbench-reports/results.sarif`;
- `delegationbench-reports/benchmark.json`.

JUnit can be consumed by ordinary test-reporting systems. SARIF 2.1.0
can be uploaded to GitHub code scanning. The JSON document includes the
DelegationBench version, Git commit, command, environment, metrics, and
complete per-scenario traces.

The action attempts both JUnit and SARIF generation before returning a
failure. This ensures that a security regression still leaves diagnostic
artifacts instead of stopping after the first report command.
