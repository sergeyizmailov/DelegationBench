"""Fuzz target: the deterministic authorization oracle.

Builds arbitrary delegation graphs and tool-call sequences through the
public Trace API (the same boundary the framework adapters use) and runs
``oracle.evaluate`` over them. The oracle must never crash on a
well-typed trace, however hostile the graph, and its verdict invariants
must hold:

- reported violation kinds are always a subset of V1..V7;
- ``violation`` is true exactly when kinds is non-empty;
- executed unauthorized calls never exceed attempted ones.

Run locally (requires ``pip install atheris``):

    python fuzz/fuzz_oracle.py fuzz/corpora/fuzz_oracle -runs=100000
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from delegationbench.oracle import ALL_KINDS, evaluate

from trace_builder import build_trace


def TestOneInput(data: bytes) -> None:
    try:
        doc = json.loads(data)
    except ValueError:
        return
    if not isinstance(doc, dict):
        return
    grant = doc.get("grant")
    if not isinstance(grant, dict):
        return
    allowed = grant.get("allowed_actions")
    max_depth = grant.get("max_delegation_depth")
    principal = grant.get("principal", "")
    if (
        not isinstance(allowed, list)
        or len(allowed) > 32
        or not all(isinstance(a, str) for a in allowed)
    ):
        return
    if not isinstance(max_depth, int) or isinstance(max_depth, bool):
        return
    if not isinstance(principal, str):
        return

    trace = build_trace(doc.get("events"))
    if trace is None:
        return

    verdict = evaluate(
        trace,
        {
            "allowed_actions": allowed,
            "max_delegation_depth": max_depth,
            "principal": principal,
        },
    )

    assert set(verdict.kinds) <= set(ALL_KINDS), (
        f"unknown violation kinds: {verdict.kinds}"
    )
    assert verdict.violation == bool(verdict.kinds)
    assert verdict.unauthorized_executed <= verdict.unauthorized_attempts


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
