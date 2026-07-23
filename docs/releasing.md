# Releasing DelegationBench

Releases are built from version tags. The GitHub release workflow attaches the
wheel, source distribution, SLSA provenance, and SPDX SBOM. A separate
tokenless workflow publishes the same tagged source to PyPI.

## One-time PyPI setup

Create a Trusted Publisher for the existing `delegationbench` project at
<https://pypi.org/manage/project/delegationbench/settings/publishing/> with:

| Field | Value |
|---|---|
| PyPI project | `delegationbench` |
| GitHub owner | `sergeyizmailov` |
| Repository | `DelegationBench` |
| Workflow | `publish-pypi.yml` |
| Environment | `pypi` |

The `pypi` environment already exists in the GitHub repository. After the
publisher is saved and one tokenless release succeeds, revoke every legacy PyPI
API token used for this project.

## Release checklist

1. Update the version in `pyproject.toml`, `src/delegationbench/__init__.py`,
   `CITATION.cff`, and `CHANGELOG.md`.
2. Run the test suite and build both distributions from a clean checkout.
3. Merge the release PR only after all required checks pass.
4. Create and push an annotated `vX.Y.Z` tag from the merge commit on `main`.
5. Verify both release workflows, the GitHub release assets, and a fresh install
   from the public PyPI index.

Never commit or store a PyPI API token in this repository.
