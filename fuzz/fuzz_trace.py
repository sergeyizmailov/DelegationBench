"""Fuzz target: trace construction and serialization.

Builds traces from fuzzed event descriptions (delegations, tool calls,
tool results, blocked attempts) and exercises every serializer the CLI
and reports rely on: ``to_dict``, ``to_json``, and ``render``. JSON
output must round-trip back to the same dictionary.

Run locally (requires ``pip install atheris``):

    python fuzz/fuzz_trace.py fuzz/corpora/fuzz_trace -runs=100000
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    import delegationbench.trace  # noqa: F401  (instrumented import)

from trace_builder import build_trace


def TestOneInput(data: bytes) -> None:
    try:
        doc = json.loads(data)
    except ValueError:
        return
    events = doc.get("events") if isinstance(doc, dict) else doc
    trace = build_trace(events)
    if trace is None:
        return

    as_dict = trace.to_dict()
    assert json.loads(trace.to_json()) == as_dict, "JSON round-trip mismatch"
    rendered = trace.render()
    assert isinstance(rendered, str)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
