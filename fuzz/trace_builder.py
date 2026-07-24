"""Shared helpers for the trace-based fuzz targets.

Builds well-typed ``Trace`` objects from fuzzed JSON event descriptions —
the same boundary the ROMA and LangGraph adapters use when they translate
framework callbacks into DelegationBench events. Only structurally valid
input reaches the trace/oracle code under test; malformed JSON is a
harness-level rejection, not a finding.
"""

from __future__ import annotations

from delegationbench.trace import Trace

_MAX_EVENTS = 64
_MAX_STR = 256
_KINDS = ("delegation", "tool_call", "tool_result", "blocked")


def _clean_str(value) -> str | None:
    if not isinstance(value, str) or len(value) > _MAX_STR:
        return None
    return value


def _clean_opt_str(value):
    if value is None:
        return None
    return _clean_str(value)


def _clean_num(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _clean_str_list(value, limit: int = 32):
    if (
        not isinstance(value, list)
        or len(value) > limit
        or not all(_clean_str(v) is not None for v in value)
    ):
        return None
    return [str(v) for v in value]


def append_event(trace: Trace, ev) -> bool:
    """Append one fuzzed event; False means the harness rejects the input."""
    if not isinstance(ev, dict):
        return False
    kind = ev.get("kind")
    if kind not in _KINDS:
        return False
    task_id = _clean_str(ev.get("task_id"))
    agent = _clean_str(ev.get("agent"))
    if task_id is None or agent is None:
        return False
    source = _clean_str(ev.get("source")) or "user"
    principal = _clean_str(ev.get("principal")) or ""
    expires = ev.get("expires_at")
    expires_at = None if expires is None else _clean_num(expires)
    if expires is not None and expires_at is None:
        return False

    if kind == "delegation":
        parent = _clean_opt_str(ev.get("parent_task"))
        scope = _clean_str_list(ev.get("scope", []))
        depth = ev.get("depth")
        nonce = _clean_str(ev.get("nonce")) or ""
        if parent is None and ev.get("parent_task") is not None:
            return False
        if scope is None or isinstance(depth, bool) or not isinstance(depth, int):
            return False
        trace.delegation(
            parent,
            task_id,
            agent,
            scope,
            depth=depth,
            nonce=nonce,
            expires_at=expires_at,
            source=source,
            principal=principal,
        )
        return True

    if kind == "tool_call":
        action = _clean_str(ev.get("action"))
        args = ev.get("args", {})
        if action is None or not isinstance(args, dict):
            return False
        trace.tool_call(
            task_id,
            agent,
            action,
            args,
            source=source,
            expires_at=expires_at,
            principal=principal,
        )
        return True

    if kind == "tool_result":
        action = _clean_str(ev.get("action"))
        result = ev.get("result")
        if action is None or not isinstance(result, str):
            return False
        trace.tool_result(
            task_id, agent, action, result, source=source, principal=principal
        )
        return True

    # blocked
    phase = _clean_str(ev.get("phase"))
    reason = _clean_str(ev.get("reason"))
    if phase is None or reason is None:
        return False
    trace.blocked(
        task_id, agent, phase=phase, reason=reason, source=source, principal=principal
    )
    return True


def build_trace(events, max_events: int = _MAX_EVENTS) -> Trace | None:
    """Build a Trace from fuzzed event dicts; None = harness rejection."""
    if not isinstance(events, list) or len(events) > max_events:
        return None
    trace = Trace()
    for ev in events:
        if not append_event(trace, ev):
            return None
    return trace
