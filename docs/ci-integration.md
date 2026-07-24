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

Exit code `0` means every scenario matched its declared no-defense baseline
and, when a defense is active, its defense contract. Exit code `1` means at
least one baseline, containment, or benign-task regression. Exit code `2`
means configuration or execution error.

Signed-envelope mode fails closed unless a key is explicitly configured:

```bash
DELEGATIONBENCH_KEY="$YOUR_CI_SECRET" \
  delegationbench run scenarios/ --defense envelope-sign
```

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
      - uses: sergeyizmailov/DelegationBench@v0.4.5
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

### Taxonomy tags

SARIF findings carry security-taxonomy metadata: each violation rule
(V1–V7) is mapped to the OWASP Agentic Top 10 (`ASI03` Identity &
Privilege Abuse, `ASI07` Insecure Inter-Agent Communication), to CWE
(e.g. `CWE-269`, `CWE-441`, `CWE-863`, `CWE-290`), and — where the
violation is delivered by indirect prompt injection (V2, V6) — to MITRE
ATLAS (`AML.T0051.001`). Full taxonomy descriptors are declared once in
`run.taxonomies`; the driver references them through
`tool.driver.supportedTaxonomies`, and each rule references individual taxa
through `relationships` plus human-readable `properties.tags`. This structure
validates against SARIF 2.1.0 and uploads to GitHub code scanning. The
`scenario-load-error` rule is deliberately untagged: it is a harness
error, not a security finding.

The action attempts both JUnit and SARIF generation before returning a
failure. This ensures that a security regression still leaves diagnostic
artifacts instead of stopping after the first report command.
