"""Execution trace: append-only deterministic log of events.

Event kinds: ``delegation``, ``tool_call``, ``tool_result``, and
``blocked`` (a defense prevented the action; carries the rejection
``reason`` and the ``phase`` at which it fired). Every event carries:

- ``time``: virtual-clock seconds when the event was recorded.
- ``source``: provenance of the content that triggered the event
  (``user`` | ``document`` | ``tool_result`` | ``child_result``). The
  oracle uses this for V6 (scope widening via result).
- envelope metadata (``depth``, ``nonce``, ``expires_at``) so the oracle
  can judge structural rules (V3, V4) without trusting the runner.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .clock import VirtualClock

SOURCES = ("user", "document", "tool_result", "child_result")

DEFAULT_MAX_EVENTS = 10_000


class RunLimitExceeded(RuntimeError):
    """Raised when the trace grows past the event cap (runaway recursion)."""


class BlockedError(RuntimeError):
    """Raised by a defense hook to prevent a delegation or tool call.

    The engine catches it, records a ``blocked`` event (with the reason)
    in the trace, and skips the action: the tool never executes and the
    delegation edge never happens.
    """


@dataclass
class Event:
    kind: str                     # "delegation" | "tool_call" | "tool_result"
    seq: int
    time: float
    parent_task: str | None
    task_id: str
    agent: str
    source: str = "user"
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "time": self.time,
            "parent_task": self.parent_task,
            "task_id": self.task_id,
            "agent": self.agent,
            "source": self.source,
            **self.detail,
        }


class Trace:
    def __init__(self, clock: VirtualClock | None = None,
                 max_events: int = DEFAULT_MAX_EVENTS) -> None:
        self.clock = clock if clock is not None else VirtualClock()
        self.max_events = max_events
        self.events: list[Event] = []

    def _append(self, event: Event) -> None:
        self.events.append(event)
        if len(self.events) > self.max_events:
            raise RunLimitExceeded(
                f"trace exceeded {self.max_events} events; "
                "aborting runaway delegation")

    def delegation(self, parent_task: str | None, task_id: str, agent: str,
                   scope, *, depth: int, nonce: str,
                   expires_at: float | None, source: str = "user",
                   task: str = "", args: dict | None = None) -> None:
        self._append(Event(
            "delegation", len(self.events), self.clock.now, parent_task,
            task_id, agent, source,
            {"scope": sorted(scope), "depth": depth, "nonce": nonce,
             "expires_at": expires_at, "task": task, "args": args or {}}))

    def tool_call(self, task_id: str, agent: str, action: str, args: dict,
                  *, source: str = "user", nonce: str = "",
                  expires_at: float | None = None) -> None:
        self._append(Event(
            "tool_call", len(self.events), self.clock.now, None, task_id,
            agent, source,
            {"action": action, "args": dict(args), "nonce": nonce,
             "expires_at": expires_at}))

    def tool_result(self, task_id: str, agent: str, action: str,
                    result: str, *, source: str = "user") -> None:
        self._append(Event(
            "tool_result", len(self.events), self.clock.now, None, task_id,
            agent, source, {"action": action, "result": result}))

    def blocked(self, task_id: str, agent: str, *, phase: str, reason: str,
                source: str = "user", parent_task: str | None = None,
                action: str | None = None, args: dict | None = None,
                scope=None, task: str = "") -> None:
        """Record a defense rejection: the action did not execute."""
        detail: dict = {"phase": phase, "reason": reason}
        if action is not None:
            detail["action"] = action
            detail["args"] = dict(args or {})
        if scope is not None:
            detail["scope"] = sorted(scope)
        if task:
            detail["task"] = task
        self._append(Event("blocked", len(self.events), self.clock.now,
                           parent_task, task_id, agent, source, detail))

    def to_dict(self) -> dict:
        return {"events": [e.to_dict() for e in self.events]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def render(self) -> str:
        lines = []
        for e in self.events:
            if e.kind == "delegation":
                src = e.parent_task or "USER"
                lines.append(
                    f"[{e.seq}] t={e.time:g} DELEGATE {src} -> {e.task_id} "
                    f"(agent={e.agent}, scope={e.detail['scope']}, "
                    f"depth={e.detail['depth']}, source={e.source})")
            elif e.kind == "tool_call":
                lines.append(
                    f"[{e.seq}] t={e.time:g} TOOL_CALL task={e.task_id} "
                    f"agent={e.agent} action={e.detail['action']} "
                    f"args={e.detail['args']} source={e.source}")
            elif e.kind == "blocked":
                what = e.detail.get("action") or e.detail.get("scope") or ""
                lines.append(
                    f"[{e.seq}] t={e.time:g} BLOCKED task={e.task_id} "
                    f"agent={e.agent} phase={e.detail['phase']} {what} "
                    f"reason={e.detail['reason']}")
            else:
                lines.append(
                    f"[{e.seq}] t={e.time:g} TOOL_RESULT task={e.task_id} "
                    f"agent={e.agent} action={e.detail['action']} "
                    f"result={e.detail['result']!r}")
        return "\n".join(lines)
