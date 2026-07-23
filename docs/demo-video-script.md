# 90-second demo video script

This script demonstrates only reproducible public evidence. Record it after the
`v0.4.0` release is public.

## 0:00-0:10 - Problem

**Visual:** repository social preview, then the README.

**Narration:**

"Multi-agent systems can give every agent sensible permissions and still lose
the user's authority boundary during a handoff. DelegationBench provides open,
deterministic crash tests for that failure."

## 0:10-0:30 - Reproduce an unsafe handoff

**Visual:** terminal.

```bash
python -m pip install \
  "delegationbench @ git+https://github.com/sergeyizmailov/DelegationBench.git@v0.4.0"
git clone --depth 1 --branch v0.4.0 \
  https://github.com/sergeyizmailov/DelegationBench.git
cd DelegationBench
delegationbench run scenarios/attacks/attack-008-malicious-document.yaml
```

**Narration:**

"Here the user granted document reading only. An invoice injects a payment
instruction, the reader hands it to a capable payment agent, and the payment
executes. The deterministic oracle reconstructs the delegation path and reports
authority expansion and confused-deputy execution."

## 0:30-0:50 - Show exact evidence

**Visual:** highlight `V1`, `V2`, `payment.execute`, and the delegation path in
the terminal report, then open the scenario YAML.

**Narration:**

"The verdict does not come from another language model. It follows the root
grant, child scope, principal, depth, expiry, nonce, origin, and tool events.
The YAML includes an exact expected verdict and side-effect contract."

## 0:50-1:08 - Run the security baseline

**Visual:** terminal.

```bash
delegationbench run scenarios/ --defense envelope-sign
```

**Narration:**

"The signed-envelope reference defense contains all attack cases while benign
twins must still complete their tasks. Blocking every action is scored as
overblocking, not success."

## 1:08-1:22 - CI and integrations

**Visual:** GitHub Actions checks, `action.yml`, and the LangGraph adapter.

**Narration:**

"The current corpus contains 75 scenarios across V1 through V7. Teams can run
it through a GitHub Action and export JSON, JUnit, SARIF, or versioned benchmark
reports. A real compiled LangGraph integration runs in required CI."

## 1:22-1:30 - Close

**Visual:** repository URL and Apache-2.0 badge.

**Narration:**

"DelegationBench is Apache-2.0 infrastructure for shared, reproducible agent
handoff security. Clone the release, reproduce the trace, and add your own
framework regression."

## Recording checklist

- Capture at 1440p or 1080p with terminal text at least 24 px.
- Use a clean temporary environment and the tagged release.
- Do not show API keys, usernames, notifications, or unrelated browser tabs.
- Keep the final edit between 75 and 90 seconds.
- Add burned-in English captions and export H.264 MP4.
- Replace no commands or results in post-production; rerun failed takes.
