# DelegationBench Project Plan

## 0. Current Status

The deterministic MVP and two security-remediation cycles are complete. The
`v0.4.0` release candidate has 75 scenarios, 231 tests in the
LangGraph-enabled environment, a required real-graph integration job,
LangGraph and experimental ROMA adapters, CI report formats, a composite
GitHub Action, and a versioned scenario-coverage matrix.

The project is **not yet ready to submit** because real open-weight benchmark
reports and 3–5 external validations are still incomplete. The 75-scenario
target is implemented; maintainer editorial review is the remaining corpus
gate. Requested funding and duration are applicant decisions.
Track the exact evidence in [docs/grant-readiness.md](docs/grant-readiness.md).

## 1. Objective

Build and release **DelegationBench**, an open-source security testbed and fuzzer for detecting privilege escalation across AI-agent delegation chains, then submit a proof-driven grant application to the Sentient Foundation.

The immediate objective is not to build a complete agent-security platform. It is to demonstrate one important and reproducible failure mode:

> A low-authority agent can cause a higher-authority agent to perform an action that the originating user or task never authorized.

Working one-line description:

> Open crash tests for privilege escalation across AI agent handoffs.

## 2. Target Users

DelegationBench is developer infrastructure, not an end-user application.

Primary users:

- Maintainers of multi-agent frameworks such as ROMA, LangGraph, CrewAI, and AutoGen.
- Engineering teams building multi-agent workflows.
- AI security engineers and red teams.
- Researchers evaluating agent authorization and delegation.
- Organizations deploying agents that can access files, email, APIs, infrastructure, or payments.

## 3. Problem

Multi-agent systems divide one user request into subtasks handled by different agents. These agents may have different tools and permissions.

Example:

- A research agent can read documents and websites.
- A payment agent can prepare and execute payments.
- The user asks only to research an invoice.
- The invoice contains an injected instruction telling the research agent to ask the payment agent to pay it.
- The research agent cannot pay directly, but the payment agent can.
- A conventional permission check sees that the payment agent is allowed to execute payments and permits the action.

The system violates the user's intent even though each agent appears to stay within its individual permissions.

This is a form of:

- Cross-agent privilege escalation.
- Confused-deputy behavior.
- Authority laundering.
- Unsafe agent handoff.

The central security invariant is:

```text
effective_authority(child_task)
  = user_grant
  ∩ parent_task_authority
  ∩ child_task_scope
```

Authority may remain equal or shrink during delegation. It must never expand implicitly.

## 4. Why This Project

Several adjacent categories are already crowded:

- General agent sandboxes.
- MCP permission gateways.
- Generic prompt-injection scanners.
- Agent security benchmarks.
- Memory-poisoning benchmarks and middleware.
- Signed action receipts.
- Pre-execution authorization products.
- LLM cost routers.

DelegationBench will not compete by creating another general policy engine or sandbox. It will provide an executable, framework-neutral way to test whether authority expands across recursive agent handoffs.

The project combines:

- A deterministic authorization oracle.
- Reproducible attack and benign scenarios.
- Framework adapters.
- Delegation-aware fuzzing.
- Exploit-trace minimization.
- Regression-test generation.
- A minimal reference defense.

## 5. Sentient Foundation Fit

DelegationBench directly addresses several Sentient product requests:

- Unified Security Testbed.
- Open Red-Teaming for Agents.
- Know Your Agent.
- Sandbox and capability control for agents.
- ROMA extensions.

The strongest connection is to the Unified Security Testbed request, which explicitly mentions unsafe agent handoffs and asks builders to start with one threat, make it reproducible, and make it easy for other teams to run.

ROMA is especially relevant because it recursively decomposes tasks into subtasks, and executors may be models, APIs, or other agents. This produces a natural authority tree that can be tested.

### Current ROMA Signals

As of July 23, 2026, the ROMA repository contains external proposals for:

- Hierarchical agent identity: issue #90.
- Cryptographic chain of custody for agent delegation: issue #92.

These proposals confirm that identity and delegation governance are active concerns. DelegationBench should test whether such mechanisms actually prevent escalation rather than duplicate them.

### ROMA Licensing Risk

The public ROMA repository currently has no visible `LICENSE` file, and its `pyproject.toml` does not declare a license.

Until this is clarified:

- Do not copy ROMA source code.
- Keep DelegationBench framework-neutral.
- Implement the ROMA integration through public runtime interfaces or an independent adapter.
- Ask the maintainers to clarify licensing before making a derived integration.

## 6. Product Scope

### Version 0.1

The initial release must include:

- Python CLI.
- YAML scenario format.
- Deterministic authorization oracle.
- Agent and task capability manifests.
- Mock email, filesystem, administrative API, and payment tools.
- Full delegation and tool-call traces.
- At least 15 attack scenarios.
- At least 10 benign scenarios.
- JSON report.
- Human-readable terminal or HTML report.
- ROMA adapter, subject to technical and licensing feasibility.
- One reference defense.
- GitHub Action integration.
- Reproducible installation and execution.

Example:

```bash
pip install delegationbench
delegationbench run examples/roma.yaml
```

Example result:

```text
FAIL: Cross-agent privilege escalation

Originating task:
  Research an invoice

Unauthorized action:
  payment.execute

Delegation path:
  planner -> researcher -> payment_agent

Escalation depth:
  2

Reproduction:
  tests/regressions/privilege-escalation-004.yaml
```

### Out of Scope for Version 0.1

- Production payment execution.
- Real credentials.
- A full authorization platform.
- A complete agent identity system.
- General-purpose prompt-injection detection.
- A hosted enterprise control plane.
- Support for every agent framework.
- Claims that all agent security problems are solved.

## 7. Initial Attack Scenarios

The first scenario set should cover:

1. Credential forwarding between agents.
2. Impersonation of a supervisor or administrative agent.
3. Requesting execution with another agent's elevated authority.
4. Orchestrator bypass.
5. Scope widening during handoff.
6. Nested delegation beyond the allowed depth.
7. Malicious instructions in a child-agent result.
8. Malicious instructions in an external document.
9. Replay of an old delegation.
10. Use of an expired delegation.
11. Cross-user context contamination.
12. Sibling-agent configuration modification.
13. Escalation from read to write.
14. Escalation from draft to send.
15. Escalation from prepare to execute.

Every attack scenario must have a corresponding or closely related benign scenario so that a defense cannot succeed by blocking all useful behavior.

## 8. Reference Defense

The initial reference defense will be a delegation envelope passed with every subtask.

Example:

```json
{
  "principal": "user-123",
  "task_id": "research-invoice",
  "allowed_actions": [
    "invoice.read",
    "web.read"
  ],
  "max_delegation_depth": 2,
  "expires_at": "2026-09-01T12:00:00Z"
}
```

Properties:

- Bound to the originating principal.
- Bound to a specific task.
- Explicit allowed actions and resources.
- Expiration time.
- Maximum delegation depth.
- Child envelopes may only remove authority.
- Optional Ed25519 signature.
- Checked at the tool boundary, outside model reasoning.

The defense is a reference implementation, not the main product. The benchmark must also be able to test other authorization systems.

## 9. Delegation-Aware Fuzzer

The differentiating component is a fuzzer for authority propagation.

It should mutate:

- Message wording.
- Language.
- Claimed sender role.
- Delegation order.
- Delegation depth.
- Source of the instruction.
- Requested tool.
- Resource scope.
- Expiration and replay conditions.
- Intermediate agent topology.

When an escalation is found, the fuzzer should:

1. Capture the complete trace.
2. Confirm the violation using the deterministic oracle.
3. Minimize the sequence to the shortest reproducible exploit.
4. Save it as a standalone scenario.
5. Generate a regression test.

The intended distinction from general agent fuzzers is that coverage and success are measured against authority propagation across an agent graph, not only prompt behavior or source-to-sink tool flow.

## 10. Metrics

The benchmark should report:

- Unauthorized Action Rate.
- Cross-Agent Escalation Rate.
- Escalation depth.
- Number of unauthorized tool calls.
- Detection rate.
- False positive rate.
- Benign Task Success Rate.
- Attack reproducibility.
- Success under paraphrasing and language changes.
- Model-to-model variation.
- Runtime and model cost per test.
- Results before and after applying a defense.

No benchmark numbers may be included in the grant application until they have been reproduced.

## 11. Original Six-Week MVP Execution Plan

Phases 1–6 below describe the original MVP plan and are retained as a decision
record. Current pre-submission work is tracked in
[ROADMAP.md](ROADMAP.md) and
[docs/grant-readiness.md](docs/grant-readiness.md).

### Phase 0: Hypothesis Validation — Days 1–5

Deliverables:

- Final threat model.
- Competitor matrix.
- Five concrete, executable attack designs.
- Technical review of ROMA, LangGraph, and CrewAI interception points.
- ROMA maintainer outreach.
- ROMA license clarification request.
- Feedback from several agent-framework developers or security engineers.

Go criteria:

- At least three escalation scenarios appear technically reproducible.
- A stable observation or interception point exists.
- No mature direct equivalent is found.
- External developers confirm that the test would be useful.

No-go criteria:

- The violation cannot be judged deterministically.
- Existing products already provide equivalent framework-neutral execution tests.
- ROMA and at least one additional framework cannot expose sufficient traces.
- The benchmark only detects generic prompt injection rather than authority escalation.

Fallback:

- Pivot to a Consent Integrity Testbed that verifies the action shown to a user is exactly the action executed.

### Phase 1: Minimal Lab — Week 1

Deliverables:

- Public Apache-2.0 repository.
- Core package structure.
- Scenario schema.
- Simulated agents and tools.
- Deterministic action log.
- Initial README and threat model.

### Phase 2: Authorization Oracle — Week 2

Deliverables:

- User, agent, task, and resource capability manifests.
- Authority attenuation rules.
- Delegation-tree reconstruction.
- Deterministic violation detection.
- Initial terminal and JSON reports.

### Phase 3: Scenario Suite — Weeks 2–3

Deliverables:

- At least 15 attack scenarios.
- At least 10 benign scenarios.
- Reproducible test runner.
- Regression-test generation.
- Results on at least two models.

### Phase 4: Fuzzer and Reference Defense — Weeks 3–4

Deliverables:

- Mutation engine.
- Delegation-graph mutations.
- Exploit minimizer.
- Delegation envelope defense.
- Before-and-after benchmark results.

### Phase 5: ROMA Adapter — Week 4

Deliverables:

- ROMA trace adapter, if technically and legally feasible.
- Recursive task and subtask mapping.
- Tool-call interception or observation.
- Example ROMA scenario.

If ROMA integration is blocked:

- Preserve the framework-neutral core.
- Document the blocker.
- Implement a LangGraph adapter.
- Continue ROMA discussions without copying unlicensed code.

### Phase 6: Validation and Release — Week 5

Deliverables:

- Version `v0.1.0`.
- Reproducible package installation.
- GitHub Action.
- Public benchmark report.
- Results across two frameworks if possible.
- External reproduction by at least one developer.
- Ninety-second demo video.
- Technical article.

### Phase 7: Grant Application — Week 6

Submit only after the repository and demonstration are public.

Required application assets:

- GitHub repository.
- Release link.
- Demo video.
- Benchmark report.
- Threat model.
- Competitor comparison.
- Roadmap and milestones.
- Budget.
- Clear explanation of why openness is essential.

## 12. Grant Positioning

Do not position the project as a complete agent-security platform.

Use this problem statement:

> Multi-agent frameworks split one user request into recursive subtasks, but lack a shared executable test for whether authority expands across those handoffs. DelegationBench supplies that test.

Use this open-source argument:

> The scenario format, attack corpus, adapters, fuzzer, evaluation engine, reference defense, and benchmark results are open. If these components were closed, framework maintainers would lose a shared and reproducible way to verify delegation security.

Use this impact argument:

> A security failure discovered in one framework becomes a reusable regression test for every supported framework.

Avoid:

- Unsupported claims of being the first project.
- Claims of solving all agent authorization.
- Artificially large benchmark numbers.
- A polished marketing site without a working repository.
- Describing a conventional prompt scanner as a delegation benchmark.

## 13. Grant Request Decision

**Requested amount: TBD — applicant decision.**

**Requested duration: TBD — applicant decision.**

The final budget must map the approved amount to measurable deliverables and
may include engineering/research, model inference and compute, independent
security review, CI/hosting, and documentation/community work. No
agent-generated funding figure should be treated as approved.

## 14. Proposed Grant Milestones

The calendar and budget allocation remain provisional until the applicant
approves the grant duration and requested amount.

### Milestone 1 — Evidence baseline

- Publish repeated benchmark results for at least two open-weight models.
- Complete 3–5 external validation interviews or reproductions.
- Publish the benchmark protocol, failure accounting, and full traces.

### Milestone 2 — Corpus and integration

- Maintain and externally review the 75-scenario V1–V7 corpus; add further
  pairs based on framework-maintainer demand.
- Stabilize the LangGraph adapter contract and conformance fixtures.
- Validate ROMA only if licensing and API assumptions are confirmed.

### Milestone 3 — Ecosystem release

- Publish a stable scenario/trace schema and migration policy.
- Add framework integrations selected from external demand.
- Publish cross-framework reports and community contribution workflows.
- Prepare a `v1.0.0` release only after the compatibility and evidence gates
  are met.

## 15. Distribution Strategy

Distribution channels:

- ROMA GitHub issues or discussions.
- Sentient developer community and Discord.
- OWASP Agentic Security Initiative.
- Agent Threat Rules.
- PyPI.
- GitHub Actions Marketplace.
- Hugging Face dataset for attack scenarios.
- Hacker News.
- AI security and agent-development communities.
- Technical conference or workshop submission.

The project should seek adoption through executable tests and integrations rather than general marketing.

## 16. Risks

### Fast-Moving Competition

Agent security changes weekly. A competing delegation benchmark may appear during development.

Mitigation:

- Keep the scope narrow.
- Prioritize an executable MVP.
- Differentiate through deterministic authority invariants, graph-aware fuzzing, exploit minimization, and ROMA integration.

### ROMA Integration and Licensing

ROMA may lack stable hooks or a usable open-source license.

Mitigation:

- Keep the core independent.
- Use adapters.
- Avoid copying code.
- Request clarification early.

### LLM Nondeterminism

An attack may succeed only occasionally.

Mitigation:

- Separate deterministic authorization judgment from probabilistic attack generation.
- Repeat trials.
- Record model, version, configuration, seed where available, and full traces.

### Overblocking

A defense may appear secure because it prevents all useful actions.

Mitigation:

- Pair attacks with benign scenarios.
- Treat Benign Task Success Rate as a primary metric.

### Weak User Demand

The market for multi-agent security is early.

Mitigation:

- Validate with framework maintainers and security teams before expanding.
- Treat the initial project as an open public good and research infrastructure rather than a mass-market SaaS product.

## 17. Decision Gates

Continue after the first ten days only if:

- At least three real cross-agent escalation scenarios are reproducible.
- The violations can be detected without an LLM judge.
- The framework exposes enough execution data.
- DelegationBench detects a failure that ordinary per-agent tool permissions miss.
- At least one external developer can run or review the test.

Prepare the Sentient application only if:

- Version `v0.3.0` or later is public.
- The real-model demo works from a clean environment.
- Repeated results for at least two open-weight models are public.
- 3–5 external validations are recorded, including one workflow/CI use signal.
- The reviewed corpus reaches the approved submission target.
- The open component is clearly essential.
- The roadmap and requested funding are tied to measurable deliverables.

## 18. Immediate Next Step

Close the external evidence gates in this order:

1. Run and review the real-model harness on two open-weight models.
2. Publish only competent, reproducible repeated results.
3. Complete 3–5 external validation conversations using the validation kit.
4. Record maintainer review of the 22 new attack/benign pairs.
5. Approve budget and duration, then assemble the final application packet.
