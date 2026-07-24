"""Fuzz target: authority envelope construction, derivation, and signing.

Builds envelopes from fuzzed JSON fields and checks the attenuation
invariants the reference defense relies on:

- a derived (child) envelope never holds actions outside the parent's;
- derivation increments depth by exactly one;
- a signed envelope verifies under its key and fails under any other key;
- ``with_principal`` only changes the principal field.

Run locally (requires ``pip install atheris``):

    python fuzz/fuzz_envelope.py fuzz/corpora/fuzz_envelope -runs=100000
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from delegationbench.envelope import Envelope

_MAX_STR = 256
_MAX_ACTIONS = 32


def _clean_str(value) -> str | None:
    if not isinstance(value, str) or len(value) > _MAX_STR:
        return None
    return value


def TestOneInput(data: bytes) -> None:
    try:
        doc = json.loads(data)
    except ValueError:
        return
    if not isinstance(doc, dict):
        return

    principal = _clean_str(doc.get("principal"))
    task_id = _clean_str(doc.get("task_id"))
    child_task = _clean_str(doc.get("child_task"))
    nonce = _clean_str(doc.get("nonce"))
    actions = doc.get("allowed_actions")
    scope = doc.get("scope")
    max_depth = doc.get("max_delegation_depth")
    depth = doc.get("depth", 0)
    expires = doc.get("expires_at")
    key = doc.get("key", "")
    other_key = doc.get("other_key", "")
    if (
        principal is None
        or task_id is None
        or child_task is None
        or nonce is None
        or not isinstance(key, str)
        or not isinstance(other_key, str)
    ):
        return
    if (
        not isinstance(actions, list)
        or len(actions) > _MAX_ACTIONS
        or not all(_clean_str(a) is not None for a in actions)
    ):
        return
    if (
        not isinstance(scope, list)
        or len(scope) > _MAX_ACTIONS
        or not all(_clean_str(a) is not None for a in scope)
    ):
        return
    if (
        not isinstance(max_depth, int)
        or isinstance(max_depth, bool)
        or not isinstance(depth, int)
        or isinstance(depth, bool)
    ):
        return
    if expires is not None and not isinstance(expires, (int, float)):
        return

    env = Envelope(
        principal=principal,
        task_id=task_id,
        allowed_actions=frozenset(actions),
        max_delegation_depth=max_depth,
        depth=depth,
        expires_at=float(expires) if expires is not None else None,
        nonce=nonce,
    )

    child = env.derive(child_task, set(scope), nonce)
    assert child.allowed_actions <= env.allowed_actions, (
        "attenuation broken: child escaped parent authority"
    )
    assert child.depth == env.depth + 1, "derive() must increment depth"

    key_bytes = key.encode("utf-8", "surrogatepass")
    other_bytes = other_key.encode("utf-8", "surrogatepass")
    signed = env.sign(key_bytes)
    assert signed.verify(key_bytes), "signature must verify under its key"
    if other_bytes != key_bytes:
        assert not signed.verify(other_bytes), (
            "signature verified under a different key"
        )

    renamed = signed.with_principal("fuzz-principal")
    assert renamed.principal == "fuzz-principal"
    assert renamed.allowed_actions == signed.allowed_actions


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
