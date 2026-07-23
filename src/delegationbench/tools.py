"""Mock tool layer.

Tools hold the content stores (docs, emails, config, payment log) seeded
from the scenario. Every call records a ``tool_call`` event and a
``tool_result`` event in the trace.

Tools enforce the calling agent's *capability manifest* (hard error if
the agent lacks the capability) — possibility, not authorization.
Authority judgment is the oracle's job, not the tool's.
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


class Tools:
    def __init__(self, trace: Trace, docs: dict[str, str] | None = None,
                 emails: dict[str, str] | None = None,
                 config: dict[str, str] | None = None) -> None:
        self.trace = trace
        self.docs = dict(docs or {})
        self.emails = dict(emails or {})
        self.config = dict(config or {})
        self.payments: list[dict] = []
        self._email_counter = 0
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
        if action not in self._handlers:
            raise ToolError(f"unknown action: {action}")
        if action not in agent.capabilities:
            raise CapabilityError(
                f"agent {agent.name!r} lacks capability {action!r} "
                f"(manifest: {sorted(agent.capabilities)})")
        self.trace.tool_call(env.task_id, agent.name, action, args,
                             source=source, nonce=env.nonce,
                             expires_at=env.expires_at)
        result = self._handlers[action](args)
        self.trace.tool_result(env.task_id, agent.name, action, result,
                               source=source)
        return result

    # -- handlers (returned value is the content the agent sees) ---------

    def _docs_read(self, args: dict) -> str:
        doc_id = str(args.get("doc_id", ""))
        if doc_id not in self.docs:
            raise UnknownResourceError(f"unknown doc_id: {doc_id!r}")
        return self.docs[doc_id]

    def _docs_write(self, args: dict) -> str:
        doc_id = str(args.get("doc_id", ""))
        self.docs[doc_id] = str(args.get("content", ""))
        return f"wrote doc {doc_id}"

    def _email_read(self, args: dict) -> str:
        email_id = str(args.get("email_id", ""))
        if email_id not in self.emails:
            raise UnknownResourceError(f"unknown email_id: {email_id!r}")
        return self.emails[email_id]

    def _email_draft(self, args: dict) -> str:
        self._email_counter += 1
        email_id = f"draft-{self._email_counter}"
        self.emails[email_id] = (
            f"To: {args.get('to', '')}\nSubject: {args.get('subject', '')}"
            f"\n\n{args.get('body', '')}")
        return f"drafted email {email_id}"

    def _email_send(self, args: dict) -> str:
        self._email_counter += 1
        email_id = f"sent-{self._email_counter}"
        self.emails[email_id] = (
            f"To: {args.get('to', '')}\nSubject: {args.get('subject', '')}"
            f"\n\n{args.get('body', '')}")
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

    def _payment(self, args: dict, status: str) -> str:
        record = {"payee": str(args.get("payee", "")),
                  "amount": str(args.get("amount", "")), "status": status}
        self.payments.append(record)
        return json.dumps(record, sort_keys=True)

    def _payment_prepare(self, args: dict) -> str:
        return self._payment(args, "prepared")

    def _payment_execute(self, args: dict) -> str:
        return self._payment(args, "executed")
