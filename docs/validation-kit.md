# External Validation Kit

Feasibility-phase item 7. Goal: show a working trace (not a pitch deck) to 4–5
potential users and record their answers. This is a human action — the materials
below are ready to send.

## Whom to approach

- ROMA maintainers (`sentient-agi/ROMA`) — also the license clarification request
  (no LICENSE file at HEAD `a6e3bb4`, README claims Apache 2.0 linking to a
  missing file). Combine both asks in one message.
- LangGraph / CrewAI framework developers.
- AI security engineers / red teams (OWASP Agentic Security Initiative, Agent
  Threat Rules maintainer — active and on the same threat class).
- Authors of adjacent work (arXiv 2503.12188 multi-agent hijack; AgentDojo team).

## The artifact to show

Real output of `experiments/minimal-escalation/experiment.py` (attack scenario):

```text
User grant: ['docs.read'], max_depth=2

[0] DELEGATE  USER -> root (agent=reader, scope=['docs.read'])
[1] TOOL_CALL task=root agent=reader action=docs.read args={'doc_id': 'inv-2041'}
[2] DELEGATE  root -> root/pay (agent=payment,
              scope=['payment.execute', 'payment.prepare'])
[3] TOOL_CALL task=root/pay agent=payment action=payment.prepare
              args={'payee': 'acme-supplier', 'amount': 950}
[4] TOOL_CALL task=root/pay agent=payment action=payment.execute
              args={'payee': 'acme-supplier', 'amount': 950}

VERDICT: VIOLATION
  - V1 authority expansion: task root/pay requested scope outside parent authority
  - V2 confused deputy: payment executed under root/pay, effective authority is []
```

And the paired benign scenario (approved payment, same chain, verdict
`NO VIOLATION`) — demonstrating the oracle distinguishes intent, not tool names.

## Questions to ask

1. Would you run a test like this in CI? If not, what stops you?
2. What real handoff/delegation scenarios exist in your system today?
3. What execution data can your framework actually expose (delegation events,
   tool calls, per-task context)? What is missing?
4. What report format would you actually consume (JSON, JUnit, SARIF, terminal)?
5. What would block an integration: APIs, licenses, time, relevance?
6. Do you know an existing tool that already does this? (final competitor check)

## Recording

Log each conversation in this file (date, person/project, answers, verbatim
quotes where permitted). The GO_NO_GO decision requires at least one external
developer confirming practical usefulness.

## Responses

_(none yet — pending outreach)_
