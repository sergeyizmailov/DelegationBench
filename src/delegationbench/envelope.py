"""Delegation envelope: the grant that travels with every task.

Authority may only shrink along a delegation edge, so ``derive()``
intersects the requested scope with the parent's allowed actions. The
envelope is the reference-defense object; the oracle re-derives the same
invariant from the trace, so the envelope itself is *not* trusted as
proof of authority.

``expires_at`` is in virtual-clock seconds (None = no expiry). ``nonce``
uniquely identifies the envelope so replayed delegations are detectable.

Envelopes may carry an optional HMAC-SHA256 ``signature`` over their
authority fields (stdlib ``hmac``/``hashlib`` only). An envelope holding
a ``signing_key`` re-signs on ``derive()``; verification happens in the
reference defense (``defense.EnvelopeGuard``), not here. HMAC is the
benchmark reference; Ed25519 is the intended production upgrade (see
PROJECT_PLAN.md §8) so that agents can verify envelopes without holding
a shared key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, replace


@dataclass(frozen=True)
class Envelope:
    principal: str
    task_id: str
    allowed_actions: frozenset[str]
    max_delegation_depth: int
    depth: int = 0
    expires_at: float | None = None
    nonce: str = ""
    signature: str = ""
    signing_key: bytes | None = field(default=None, repr=False,
                                      compare=False)

    def _payload(self) -> bytes:
        """Canonical serialization of the authority fields being signed."""
        return json.dumps({
            "principal": self.principal,
            "task_id": self.task_id,
            "allowed_actions": sorted(self.allowed_actions),
            "max_delegation_depth": self.max_delegation_depth,
            "depth": self.depth,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, key: bytes) -> "Envelope":
        """Return a copy signed with ``key``; the copy re-signs on derive."""
        sig = hmac.new(key, self._payload(), hashlib.sha256).hexdigest()
        return replace(self, signature=sig, signing_key=key)

    def verify(self, key: bytes) -> bool:
        """True iff ``signature`` is a valid HMAC of this envelope."""
        expected = hmac.new(key, self._payload(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def derive(self, task_id: str, scope: set[str] | frozenset[str],
               nonce: str) -> "Envelope":
        """Child envelope: attenuation-only (intersection)."""
        child = Envelope(
            principal=self.principal,
            task_id=task_id,
            allowed_actions=self.allowed_actions & frozenset(scope),
            max_delegation_depth=self.max_delegation_depth,
            depth=self.depth + 1,
            expires_at=self.expires_at,
            nonce=nonce,
            signing_key=self.signing_key,
        )
        if self.signing_key is not None:
            child = child.sign(self.signing_key)
        return child

    def with_principal(self, principal: str) -> "Envelope":
        """Copy stamped with a different principal (V7 modeling).

        The orchestrator is the trusted stamper of principals — and it can
        be *deceived* into stamping another principal's identity onto an
        envelope (cross-user context confusion). It holds the signing key,
        so the substituted envelope is re-signed and still verifies: a
        signature proves the envelope was issued by the orchestrator, not
        that the principal is the one who issued the root task.
        """
        substituted = replace(self, principal=principal, signature="")
        if self.signing_key is not None:
            substituted = substituted.sign(self.signing_key)
        return substituted
