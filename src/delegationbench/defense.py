"""Reference defense: the delegation-envelope guard.

Enforcement lives at the tool boundary, outside model reasoning
(THREAT_MODEL.md §5). The guard hooks the runner's ``Defense`` protocol
and raises ``trace.BlockedError`` to reject an action; the engine records
a ``blocked`` event and the action never executes.

``before_delegation`` rejects:

- V1 — requested scope is not a subset of the parent's effective authority.
- V3 — child depth would exceed ``max_delegation_depth``.
- V4 — the child envelope is expired at the current virtual time, or its
  nonce was already used for a delegation (replay).
- Forgery — with signing enabled, an envelope whose signature does not
  verify.

``before_tool_call`` rejects:

- V5 — the issuing task has no delegation path to the root (the guard
  never saw an approved delegation for it).
- V7 — the envelope's principal differs from the root grant's principal
  (principal substitution), checked at both the delegation and the
  tool-call boundary.
- V4 — the envelope is expired at the current virtual time.
- V6 — the triggering content is a ``child_result`` and the action lies
  outside the root grant.
- V2 — the action lies outside the issuing task's effective authority.
- Forgery — with signing enabled, an envelope whose signature does not
  verify.

Signatures (``--defense envelope-sign``) use HMAC-SHA256 from the stdlib
(``hmac``/``hashlib``) — no new dependencies. Ed25519 is the intended
production upgrade (PROJECT_PLAN.md §8): asymmetric signatures would let
agents verify envelopes without sharing the signing key. The HMAC key
comes from the ``DELEGATIONBENCH_KEY`` environment variable; when unset,
``DEFAULT_SIGNING_KEY`` is used — an INSECURE fixed test key that exists
only so benchmark runs stay reproducible. Never rely on the default
outside tests.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from .trace import BlockedError

if TYPE_CHECKING:
    from .agents import Agent
    from .clock import VirtualClock
    from .envelope import Envelope

# INSECURE: fixed test key, used only when DELEGATIONBENCH_KEY is unset.
DEFAULT_SIGNING_KEY = b"delegationbench-insecure-default-key"

# Task id the runner assigns to the root envelope (runner.run_scenario).
ROOT_TASK_ID = "root"


def signing_key_from_env(env_var: str = "DELEGATIONBENCH_KEY") -> bytes:
    """HMAC key for ``--defense envelope-sign`` (insecure default if unset)."""
    return os.environ.get(env_var, "").encode("utf-8") or DEFAULT_SIGNING_KEY


class EnvelopeGuard:
    """Reference defense implementing the runner's ``Defense`` protocol."""

    def __init__(self, signing_key: bytes | None = None) -> None:
        self.signing_key = signing_key
        self._clock: VirtualClock | None = None
        self._root_grant: frozenset[str] = frozenset()
        self._root_principal: str | None = None
        self._seen_nonces: set[str] = set()
        self._known_tasks: set[str] = set()

    def bind(self, clock: "VirtualClock", grant_actions,
             principal: str | None = None) -> None:
        """Called by the runner before the run starts: supplies the virtual
        clock (for expiry checks), the root grant (for V6 checks), and the
        root principal (for V7 checks)."""
        self._clock = clock
        self._root_grant = frozenset(grant_actions)
        self._root_principal = principal or None
        self._seen_nonces.clear()
        self._known_tasks.clear()
        self._known_tasks.add(ROOT_TASK_ID)

    # -- hooks -------------------------------------------------------------

    def before_delegation(self, agent: "Agent", parent: "Envelope",
                          child: "Envelope", task: str,
                          scope: frozenset[str]) -> None:
        self._check_signature(parent)
        self._check_signature(child)
        self._check_principal(child)
        if not frozenset(scope) <= parent.allowed_actions:
            raise BlockedError(
                f"V1 authority expansion: task {child.task_id} requested "
                f"scope {sorted(scope)} outside parent authority "
                f"{sorted(parent.allowed_actions)}")
        if child.depth > child.max_delegation_depth:
            raise BlockedError(
                f"V3 depth violation: task {child.task_id} would sit at "
                f"depth {child.depth} > max_delegation_depth "
                f"{child.max_delegation_depth}")
        if child.expires_at is not None and self._now() > child.expires_at:
            raise BlockedError(
                f"V4 expired delegation: envelope for task {child.task_id} "
                f"expired at t={child.expires_at:g}, used at "
                f"t={self._now():g}")
        if child.nonce in self._seen_nonces:
            raise BlockedError(
                f"V4 replayed delegation: envelope nonce {child.nonce!r} "
                f"already used for a delegation (task {child.task_id})")
        # Approved: register the nonce and both ends of the new edge.
        self._seen_nonces.add(child.nonce)
        self._known_tasks.add(parent.task_id)
        self._known_tasks.add(child.task_id)

    def before_tool_call(self, agent: "Agent", env: "Envelope", action: str,
                         args: dict, source: str) -> None:
        self._check_signature(env)
        if env.task_id not in self._known_tasks:
            raise BlockedError(
                f"V5 origin loss: tool call {action} from task "
                f"{env.task_id} has no delegation path to the root")
        self._check_principal(env)
        if env.expires_at is not None and self._now() > env.expires_at:
            raise BlockedError(
                f"V4 expired tool call: {action} under task {env.task_id} "
                f"at t={self._now():g}, envelope expired at "
                f"t={env.expires_at:g}")
        if source == "child_result" and action not in self._root_grant:
            raise BlockedError(
                f"V6 scope widening via result: {action} under task "
                f"{env.task_id} triggered by a child result; action is "
                f"outside the root grant {sorted(self._root_grant)}")
        if action not in env.allowed_actions:
            raise BlockedError(
                f"V2 confused deputy: agent {agent.name} may not execute "
                f"{action} under task {env.task_id}; effective authority "
                f"is {sorted(env.allowed_actions)}")

    # -- internals ----------------------------------------------------------

    def _now(self) -> float:
        return self._clock.now if self._clock is not None else 0.0

    def _check_principal(self, env: "Envelope") -> None:
        """V7: the envelope's principal must equal the root grant's.

        Only enforced when the runner bound a root principal; an empty
        root principal means the run makes no principal claim to check
        against."""
        if (self._root_principal is not None
                and env.principal != self._root_principal):
            raise BlockedError(
                f"V7 principal substitution: envelope for task "
                f"{env.task_id} carries principal {env.principal!r}, "
                f"but the root grant belongs to "
                f"{self._root_principal!r}")

    def _check_signature(self, env: "Envelope") -> None:
        if self.signing_key is not None and not env.verify(self.signing_key):
            raise BlockedError(
                f"forged envelope: signature on task {env.task_id} does "
                "not verify")
