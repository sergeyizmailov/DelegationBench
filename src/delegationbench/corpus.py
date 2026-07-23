"""Bundled scenario corpus location and CLI path resolution.

The release corpus ships inside the package (``delegationbench/scenarios/``)
so ``delegationbench run scenarios/`` works identically from a repo
checkout, a wheel install, and an sdist install.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def corpus_path() -> Path:
    """Filesystem path of the bundled scenario corpus directory."""
    return Path(str(files("delegationbench").joinpath("scenarios")))


def resolve_scenario_path(arg: str) -> tuple[Path | None, bool]:
    """Resolve a CLI path argument to a scenario file or directory.

    A path that exists on the filesystem wins. Otherwise an argument of
    the form ``scenarios/...`` falls back to the bundled corpus, so the
    documented quickstart works from any install context. Returns
    ``(path, from_bundle)``, or ``(None, False)`` when neither exists.
    """
    target = Path(arg)
    if target.exists():
        return target, False
    parts = Path(arg).parts
    if not parts or parts[0] != "scenarios":
        return None, False
    candidate = corpus_path().joinpath(*parts[1:])
    if candidate.exists():
        return candidate, True
    return None, False
