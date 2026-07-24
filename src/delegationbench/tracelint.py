"""Adapter trace linter (``delegationbench validate-adapter``).

Framework adapters translate live agent-framework callbacks into
DelegationBench traces. A misconfigured adapter — a missing action_map
entry, a lost task link, a dropped principal, a broken delegation edge —
silently turns into a misleading oracle verdict: the verdict then says
something about the *adapter bug*, not about the system under test.

This module lints a recorded trace (the JSON shape produced by
``Trace.to_json()`` and by ``build_trace()`` in the adapters) for those
structural problems *before* the oracle runs, so adapter
misconfiguration is caught as a configuration error rather than
misreported as an agent violation. It checks the symptoms of mapping
problems in the trace itself; the mapping configuration lives in the
adapter and is not part of the trace.

Severity model: ``error`` findings mean the trace is ambiguous or
incomplete — the oracle cannot attribute authority unambiguously, so any
verdict over it is unreliable. ``warning`` findings are suspicious but
judgable. ``--strict`` fails on warnings too.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ERROR = "error"
WARNING = "warning"

_KINDS = ("delegation", "tool_call", "tool_result", "blocked")


@dataclass
class Finding:
    severity: str
    code: str
    message: str

    def to_dict(self) -> dict:
        return {"severity": self.severity, "code": self.code, "message": self.message}


class TraceLintError(ValueError):
    """The input cannot be read as a trace at all (usage-level error)."""


def load_trace_document(path: str | Path) -> object:
    """Read a trace JSON file; raises TraceLintError on any failure."""
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise TraceLintError(f"{path}: cannot read file: {e}") from e
    try:
        return json.loads(raw)
    except ValueError as e:
        raise TraceLintError(f"{path}: invalid JSON: {e}") from e


def _events_of(doc: object) -> list:
    """Extract the event list from a trace document."""
    if isinstance(doc, dict):
        events = doc.get("events")
        if isinstance(events, list):
            return events
        raise TraceLintError("trace object must contain an 'events' list")
    if isinstance(doc, list):
        return doc
    raise TraceLintError(
        "trace must be a JSON object with an 'events' list or a bare event list"
    )


def lint_trace(
    doc: object, *, actions: frozenset[str] = frozenset(), root_principal: str = ""
) -> list[Finding]:
    """Lint a parsed trace document; returns findings, worst first.

    ``actions`` is the effective action vocabulary (scenario-declared ∪
    grant ∪ built-ins); when non-empty, tool actions outside it are
    flagged as likely missing action_map entries. ``root_principal`` is
    the grant's principal; when known, events without a principal are
    findings (the oracle fails closed on principal continuity, so an
    adapter that drops principals invalidates the run).
    """
    findings: list[Finding] = []

    def add(severity: str, code: str, message: str) -> None:
        findings.append(Finding(severity, code, message))

    events = _events_of(doc)
    if not events:
        add(ERROR, "E-EMPTY", "trace contains no events")
        return findings

    delegated: dict[str, tuple[str | None, str]] = {}  # task -> (parent, agent)
    depth_of: dict[str, int] = {}
    expiry_of: dict[str, float | None] = {}
    nonces: dict[str, str] = {}  # nonce -> first task
    root_count = 0
    principal_known = root_principal

    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            add(ERROR, "E-SCHEMA", f"event #{i} is not an object")
            continue
        kind = ev.get("kind")
        task_id = ev.get("task_id")
        agent = ev.get("agent")
        if kind not in _KINDS:
            add(
                ERROR,
                "E-SCHEMA",
                f"event #{i}: unknown kind {kind!r} "
                f"(expected one of {', '.join(_KINDS)})",
            )
            continue
        if not isinstance(task_id, str) or not task_id:
            add(ERROR, "E-SCHEMA", f"event #{i} ({kind}): missing task_id")
            continue
        if not isinstance(agent, str) or not agent:
            add(ERROR, "E-SCHEMA", f"event #{i} ({kind}): missing agent")
            continue

        principal = ev.get("principal") or ""
        if kind == "delegation" and ev.get("parent_task") is None:
            root_count += 1
            if not principal_known and principal:
                principal_known = principal

        if principal_known and not principal:
            add(
                ERROR,
                "E-MISSING-PRINCIPAL",
                f"event #{i} ({kind} task={task_id}): no principal under "
                f"a principal-bearing root grant ({principal_known!r}); "
                "the adapter must propagate the originating user",
            )

        if kind == "delegation":
            parent = ev.get("parent_task")
            binding = (parent, agent)
            if task_id in delegated and delegated[task_id] != binding:
                add(
                    ERROR,
                    "E-REBIND",
                    f"task {task_id!r} delegated again with a different "
                    f"(parent, agent): was {delegated[task_id]}, now "
                    f"{binding}; adapters must not recycle task ids",
                )
            elif task_id not in delegated:
                if parent is not None and parent not in delegated:
                    later = any(
                        isinstance(e2, dict)
                        and e2.get("kind") == "delegation"
                        and e2.get("task_id") == parent
                        for e2 in events[i + 1 :]
                    )
                    if later:
                        add(
                            WARNING,
                            "W-OUT-OF-ORDER",
                            f"delegation of {task_id!r} precedes the "
                            f"delegation of its parent {parent!r}; "
                            "post-hoc adapters must order delegations "
                            "before child events",
                        )
                    else:
                        add(
                            ERROR,
                            "E-BROKEN-PARENT",
                            f"delegation of {task_id!r} references parent "
                            f"{parent!r}, which is never delegated; "
                            "broken delegation link",
                        )
            scope = ev.get("scope")
            if scope is not None and not isinstance(scope, list):
                add(
                    WARNING,
                    "W-SCHEMA",
                    f"delegation of {task_id!r}: scope is not a list",
                )
            if isinstance(scope, list) and not scope:
                add(
                    WARNING,
                    "W-EMPTY-SCOPE",
                    f"delegation of {task_id!r} carries an empty scope",
                )

            derived_depth = 0 if parent is None else depth_of.get(parent, 0) + 1
            reported_depth = ev.get("depth")
            if (
                isinstance(reported_depth, int)
                and not isinstance(reported_depth, bool)
                and reported_depth != derived_depth
            ):
                add(
                    WARNING,
                    "W-DEPTH-INCONSISTENT",
                    f"delegation of {task_id!r} reports depth "
                    f"{reported_depth} but the delegation graph gives "
                    f"{derived_depth}; the oracle re-derives depth, so "
                    "fix the adapter metadata",
                )
            parent_expiry = None if parent is None else expiry_of.get(parent)
            own_expiry = ev.get("expires_at")
            if (
                parent_expiry is not None
                and isinstance(own_expiry, (int, float))
                and not isinstance(own_expiry, bool)
                and own_expiry > parent_expiry
            ):
                add(
                    WARNING,
                    "W-EXPIRY-WIDENING",
                    f"delegation of {task_id!r} expiry {own_expiry} "
                    f"exceeds parent expiry {parent_expiry}",
                )
            nonce = ev.get("nonce") or ""
            if nonce and nonce in nonces and nonces[nonce] != task_id:
                add(
                    WARNING,
                    "W-DUP-NONCE",
                    f"delegation nonce {nonce!r} is shared by tasks "
                    f"{nonces[nonce]!r} and {task_id!r}; nonces must be "
                    "unique per envelope for replay detection to work",
                )
            if nonce:
                nonces.setdefault(nonce, task_id)
            delegated[task_id] = binding
            depth_of[task_id] = derived_depth
            if parent_expiry is None:
                expiry_of[task_id] = (
                    own_expiry if isinstance(own_expiry, (int, float)) else None
                )
            else:
                expiry_of[task_id] = (
                    min(parent_expiry, own_expiry)
                    if isinstance(own_expiry, (int, float))
                    and not isinstance(own_expiry, bool)
                    else parent_expiry
                )
            continue

        # tool_call / tool_result / blocked
        if task_id not in delegated:
            add(
                WARNING,
                "W-ORPHAN-TASK",
                f"event #{i} ({kind} task={task_id} agent={agent}): task "
                "was never delegated; the call cannot be attributed to a "
                "delegation path (origin loss)",
            )
        elif delegated[task_id][1] != agent:
            add(
                ERROR,
                "E-AGENT-MISMATCH",
                f"event #{i} ({kind} task={task_id}): issued by agent "
                f"{agent!r} but the task was delegated to "
                f"{delegated[task_id][1]!r}",
            )
        action = ev.get("action")
        if (
            kind in ("tool_call", "tool_result")
            and isinstance(action, str)
            and action
            and actions
            and action not in actions
        ):
            add(
                WARNING,
                "W-UNMAPPED-ACTION",
                f"event #{i} ({kind}): action {action!r} is outside the "
                "scenario action vocabulary — probable missing action_map "
                "entry (raw framework tool name reaching the trace)",
            )

    if root_count == 0:
        add(
            ERROR,
            "E-NO-ROOT",
            "no root delegation (parent_task=null); the trace has no "
            "authority origin to judge against",
        )
    elif root_count > 1:
        add(
            ERROR,
            "E-MULTI-ROOT",
            f"{root_count} root delegations; exactly one authority "
            "origin is expected per run",
        )

    order = {ERROR: 0, WARNING: 1}
    findings.sort(key=lambda f: order[f.severity])
    return findings


def render_findings(findings: list[Finding], source: str) -> str:
    """Human-readable lint report."""
    errors = sum(f.severity == ERROR for f in findings)
    warnings = sum(f.severity == WARNING for f in findings)
    lines = [f"adapter trace lint: {source}"]
    if not findings:
        lines.append("  no findings — trace structure is unambiguous")
    for f in findings:
        lines.append(f"  {f.severity.upper():<8}{f.code:<22}{f.message}")
    lines.append(f"{errors} error(s), {warnings} warning(s)")
    return "\n".join(lines)
