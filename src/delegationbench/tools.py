"""Mock tool layer.

Tools hold the content stores (docs, emails, config, payment log) seeded
from the scenario. Every call records a ``tool_call`` event and a
``tool_result`` event in the trace.

Tools enforce the calling agent's *capability manifest* (hard error if
the agent lacks the capability) — possibility, not authorization.
Authority judgment is the oracle's job, not the tool's.

Actions without a built-in handler (scenario-declared custom actions)
execute via a generic fallback: the call is recorded and a synthetic
``{"status": "ok", "action": <id>}`` result is returned, so
framework-neutral scenarios can extend the action vocabulary without
editing the package.

``payment.execute`` consults the config store's ``payment_limit``: an
execute above the limit fails with an error result and the payment is
NOT recorded as executed. This makes sibling state contamination (one
agent raising the limit so another can pay) technically real.

``outcome_state()`` exposes the final tool/store state as a small set of
generic counters (per store, plus ``config_unchanged``) so a scenario's
``expect.outcomes`` contract can assert that the task's side effects
actually happened — a benign scenario where the agent did nothing must
not count as a success.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from . import actions as act
from .trace import Trace

if TYPE_CHECKING:
    from .agents import Agent
    from .envelope import Envelope


class ToolError(RuntimeError):
    pass


class CapabilityError(ToolError):
    """Agent invoked an action outside its capability manifest."""


class UnknownResourceError(ToolError):
    pass


PAYMENT_LIMIT_KEY = "payment_limit"

# Keys a scenario may assert in ``expect.outcomes``: per-store counters
# over executed tool calls, plus ``config_unchanged`` (the config store
# equals its initial state). Counter values are integers;
# ``config_unchanged`` is a boolean.
OUTCOME_COUNTERS = ("docs_read", "docs_written", "emails_read",
                    "emails_sent", "drafts_created", "payments_prepared",
                    "payments_executed")
OUTCOME_KEYS = frozenset(OUTCOME_COUNTERS) | {"config_unchanged"}


class Tools:
    def __init__(self, trace: Trace, docs: dict[str, str] | None = None,
                 emails: dict[str, str] | None = None,
                 config: dict[str, str] | None = None) -> None:
        self.trace = trace
        self.docs = dict(docs or {})
        self.emails = dict(emails or {})
        self.config = dict(config or {})
        self._initial_config = dict(self.config)
        self.payments: list[dict] = []
        self._email_counter = 0
        self._counts = dict.fromkeys(OUTCOME_COUNTERS, 0)
        self._handlers = {
            act.DOCS_READ: self._docs_read,
            act.DOCS_WRITE: self._docs_write,
            act.EMAIL_READ: self._email_read,
            act.EMAIL_DRAFT: self._email_draft,
            act.EMAIL_SEND: self._email_send,
            act.ADMIN_CONFIG_READ: self._config_read,
            act.ADMIN_CONFIG_UPDATE: self._config_update,
            act.PAYMENT_PREPARE: self._payment_prepare,
            act.PAYMENT_EXECUTE: self._payment_execute,
        }

    def call(self, agent: "Agent", env: "Envelope", action: str,
             args: dict, source: str) -> str:
        """Execute an action, trace call + result, return result content."""
        if action not in agent.capabilities:
            raise CapabilityError(
                f"agent {agent.name!r} lacks capability {action!r} "
                f"(manifest: {sorted(agent.capabilities)})")
        self.trace.tool_call(env.task_id, agent.name, action, args,
                             source=source, nonce=env.nonce,
                             expires_at=env.expires_at,
                             principal=env.principal)
        handler = self._handlers.get(action)
        result = handler(args) if handler is not None \
            else self._generic(action, args)
        self.trace.tool_result(env.task_id, agent.name, action, result,
                               source=source, principal=env.principal)
        return result

    def outcome_state(self) -> dict:
        """Final tool/store state for the ``expect.outcomes`` contract."""
        state = dict(self._counts)
        state["payments_prepared"] = sum(
            1 for p in self.payments if p["status"] == "prepared")
        state["payments_executed"] = sum(
            1 for p in self.payments if p["status"] == "executed")
        state["config_unchanged"] = self.config == self._initial_config
        return state

    # -- handlers (returned value is the content the agent sees) ---------

    def _generic(self, action: str, args: dict) -> str:
        """Fallback for scenario-declared custom actions: record the call
        and return a synthetic result. No side effects."""
        return json.dumps({"status": "ok", "action": action},
                          sort_keys=True)

    def _docs_read(self, args: dict) -> str:
        doc_id = str(args.get("doc_id", ""))
        if doc_id not in self.docs:
            raise UnknownResourceError(f"unknown doc_id: {doc_id!r}")
        self._counts["docs_read"] += 1
        return self.docs[doc_id]

    def _docs_write(self, args: dict) -> str:
        doc_id = str(args.get("doc_id", ""))
        self.docs[doc_id] = str(args.get("content", ""))
        self._counts["docs_written"] += 1
        return f"wrote doc {doc_id}"

    def _email_read(self, args: dict) -> str:
        email_id = str(args.get("email_id", ""))
        if email_id not in self.emails:
            raise UnknownResourceError(f"unknown email_id: {email_id!r}")
        self._counts["emails_read"] += 1
        return self.emails[email_id]

    def _email_draft(self, args: dict) -> str:
        self._email_counter += 1
        email_id = f"draft-{self._email_counter}"
        self.emails[email_id] = (
            f"To: {args.get('to', '')}\nSubject: {args.get('subject', '')}"
            f"\n\n{args.get('body', '')}")
        self._counts["drafts_created"] += 1
        return f"drafted email {email_id}"

    def _email_send(self, args: dict) -> str:
        self._email_counter += 1
        email_id = f"sent-{self._email_counter}"
        self.emails[email_id] = (
            f"To: {args.get('to', '')}\nSubject: {args.get('subject', '')}"
            f"\n\n{args.get('body', '')}")
        self._counts["emails_sent"] += 1
        return f"sent email {email_id}"

    def _config_read(self, args: dict) -> str:
        key = str(args.get("key", ""))
        if key not in self.config:
            raise UnknownResourceError(f"unknown config key: {key!r}")
        return str(self.config[key])

    def _config_update(self, args: dict) -> str:
        key = str(args.get("key", ""))
        self.config[key] = str(args.get("value", ""))
        return f"config {key} updated"

    def _payment_limit(self) -> int:
        raw = self.config.get(PAYMENT_LIMIT_KEY)
        if raw is None:
            raise UnknownResourceError(
                f"unknown config key: {PAYMENT_LIMIT_KEY!r} "
                "(required by payment.execute)")
        try:
            return int(str(raw))
        except ValueError:
            raise ToolError(
                f"config {PAYMENT_LIMIT_KEY!r} must be an integer, "
                f"got {raw!r}") from None

    def _payment(self, args: dict, status: str) -> str:
        record = {"payee": str(args.get("payee", "")),
                  "amount": str(args.get("amount", "")), "status": status}
        self.payments.append(record)
        return json.dumps(record, sort_keys=True)

    def _payment_prepare(self, args: dict) -> str:
        return self._payment(args, "prepared")

    def _payment_execute(self, args: dict) -> str:
        limit = self._payment_limit()
        try:
            amount = int(str(args.get("amount", "")))
        except ValueError:
            raise ToolError(
                f"payment amount must be an integer, "
                f"got {args.get('amount')!r}") from None
        if amount > limit:
            # Refused: the payment is NOT recorded as executed.
            return json.dumps(
                {"status": "error",
                 "error": f"amount {amount} exceeds "
                          f"payment_limit {limit}",
                 "payee": str(args.get("payee", "")),
                 "amount": str(args.get("amount", ""))},
                sort_keys=True)
        return self._payment(args, "executed")
