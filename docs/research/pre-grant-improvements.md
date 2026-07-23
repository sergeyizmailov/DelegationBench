# Pre-Grant Improvement Research — DelegationBench

Research date: 2026-07-23. Scope: supply-chain trust features, SARIF/taxonomy mapping,
agent-security landscape freshness check, Python packaging must-dos, and Sentient
grant-reviewer lens — ahead of the Sentient Foundation grant submission.

## Executive summary

No blockers. The repo's packaging metadata is already PEP 639-compliant, and no direct
competitor doing deterministic delegation-chain privilege-escalation testing was found
(the closest 2026 work is a per-call authorization gate, not a scenario testbed). The
highest-value pre-submission work is cheap: (1) PyPI Trusted Publishing + PEP 740
attestations in one workflow, (2) OpenSSF Scorecard action + badge, (3) map SARIF rules
to the OWASP Agentic Top 10 (ASI01–ASI10, the accepted 2026 taxonomy) with CWE +
MITRE ATLAS cross-references, (4) frame the grant narrative around ROMA's open
identity/governance issues #90/#92 — ROMA is stale (last push 2026-02-16), still has no
LICENSE file, and those two issues sit exactly in DelegationBench's problem space.
The PyPI name `delegationbench` is unclaimed (HTTP 404 on 2026-07-23) — register it.

## 1. Supply-chain / trust features

All six items are feasible; four are one-workflow-each quick wins.

### 1a. PyPI Trusted Publishing (OIDC) — do this first
- What: short-lived OIDC token from GitHub Actions replaces a long-lived PyPI API
  token. One-time setup in PyPI project settings (owner/repo/workflow-name/environment),
  then `pypa/gh-action-pypi-publish@release/v1` with `id-token: write` and no password.
- Why: stolen PyPI tokens are the dominant PyPI compromise vector in 2026 (durabletask
  incident, 2026-07). A security-testbed repo publishing with a long-lived token would
  be an own goal. Since v1.11.0 the action also generates PEP 740 Sigstore attestations
  by default, so Sigstore signing (1d) comes free with this one step.
- Next step: create the PyPI project (name is free), configure trusted publisher,
  add `release.yml` (build job → publish job with `environment: pypi` + required reviewer).
- Effort: S.
- Sources: https://docs.pypi.org/trusted-publishers/,
  https://packaging.python.org/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/,
  https://safedep.io/malicious-durabletask-pypi-supply-chain-attack

### 1b. Publish-workflow hardening (mandatory companion to 1a)
- What: never trigger publish on `pull_request_target`; pin actions by SHA; require a
  GitHub Environment approval for the publish job.
- Why: the May 2026 TanStack compromise published 84 malicious npm packages *with valid
  OIDC provenance* by poisoning a shared workflow cache via `pull_request_target` and
  extracting the OIDC token from runner memory. Trusted publishing alone is not enough;
  reviewers who follow 2026 incidents will check the trigger model.
- Next step: tag-push or release-event trigger only; no cache sharing between PR and
  release workflows; environment protection rule on `pypi`.
- Effort: S (part of the same `release.yml`).
- Sources: https://cybelangel.com/blog/tanstack-npm-supply-chain-attack/,
  https://www.threatlocker.com/blog/teampcp-supply-chain-attack-hits-tanstack

### 1c. OpenSSF Scorecard action + badge
- What: `ossf/scorecard-action@v2` on weekly cron + push, results uploaded to code
  scanning; README badge from `api.securityscorecards.dev`. Scorecard v5.5 line current
  (v6 with OSPS Baseline conformance engine on the 2026 roadmap).
- Why: the de-facto "is this repo maintained sanely" signal for grant reviewers and
  downstream adopters; catches missing branch protection, unpinned actions, token
  permissions.
- Next step: add `.github/workflows/scorecard.yml`, enable branch protection on `main`,
  add badge to README.
- Effort: S (raising the score may surface a few repo-settings fixes — allow half a day).
- Sources: https://github.com/ossf/scorecard, https://scorecard.dev/

### 1d. Sigstore signing / PEP 740 attestations
- What: covered automatically by 1a for PyPI artifacts (attestations default-on in
  gh-action-pypi-publish ≥ v1.11.0). For GitHub Release tarballs, add
  `actions/attest-build-provenance` (GitHub Artifact Attestations, free for public repos)
  — this doubles as SLSA Build L3 provenance.
- Why: PyPI is at "L3" on the 2026 registry provenance ladder; attestations are the
  verification story reviewers expect from a security tool ("how do I trust your wheel?").
- Next step: nothing extra for PyPI; add attest step for release artifacts.
- Effort: S.
- Sources: https://github.com/astral-sh/attest-action (only needed if publishing via
  `uv publish`), https://zenn.dev/sqer/articles/e4df3d397f5651?locale=en

### 1e. SBOM generation
- What: `anchore/sbom-action` (Syft) or CycloneDX SBOM attached to each release.
- Why: low intrinsic value for a one-dependency package (PyYAML), but the 2026 agentic
  security discourse (OWASP ASI04) has made AIBOM/SBOM an expected artifact for anything
  in the agent-security space. Cheap checkbox, credible signal.
- Next step: add SBOM step to release workflow, attach `sbom.spdx.json` to the release.
- Effort: S.
- Sources: https://github.com/rmednitzer/platform-blueprint (SPDX 3.0.1 / CycloneDX 1.7
  as current format references)

### 1f. SLSA provenance
- What: `actions/attest-build-provenance` on dist artifacts gives SLSA Build L3;
  `slsa-framework/slsa-github-generator` generic builder is the alternative.
  PEP 740 attestations on PyPI are treated as L3-equivalent.
- Why: a "SLSA 3" badge is increasingly common on security-tool READMEs.
- Next step: covered by 1d; optionally add the badge.
- Effort: S.
- Sources: https://github.com/slsa-framework/slsa-github-generator/blob/main/internal/builders/generic/README.md

### 1g. OpenSSF Best Practices badge (bestpractices.dev) — optional
- What: self-certification questionnaire; "passing" level needs documented contribution,
  security, and release processes — most of which this repo already has
  (CONTRIBUTING.md, SECURITY.md, CHANGELOG.md).
- Why: nice-to-have; Scorecard badge is the higher-signal one. Gold tier is blocked for
  solo-maintainer projects (requires ≥2 contributors).
- Next step: fill in the passing-level questionnaire if time permits.
- Effort: M (questionnaire tedium, not code).
- Source: https://tac.aswf.io/process/best_practices_badge.html

## 2. SARIF / CWE / taxonomy

### 2a. Accepted 2026 taxonomy: OWASP Top 10 for Agentic Applications (ASI01–ASI10)
- What: published 2025-12-09 by the OWASP GenAI Security Project (Agentic Security
  Initiative); the reference agent-risk list as of 2026. Direct fits for DelegationBench:
  ASI03 Identity & Privilege Abuse (per-agent identity, scoped credentials),
  ASI07 Insecure Inter-Agent Communication (replayed/forged delegation messages),
  ASI08 Cascading Failures.
- Why: this is the vocabulary a 2026 reviewer uses. Rule IDs that read
  "maps to ASI03" are immediately legible; a bespoke taxonomy is not.
- Next step: add an `owasp_asi` field per scenario/rule, emit it in SARIF
  `reportingDescriptor.properties` (tags + helpUri to genai.owasp.org) and in the
  Markdown/HTML report.
- Effort: M (mapping table + reporter changes).
- Sources: https://genai.owasp.org/,
  https://cycode.com/blog/owasp-top-10-agentic-applications/

### 2b. MITRE ATLAS cross-reference
- What: ATLAS added 14 agentic-AI techniques in Oct 2025 (incl. "Exfiltration via AI
  Agent Tool Invocation"); the Feb 2026 update (v5.4.0) added more agent-focused
  techniques; matrix now ~15 tactics / 66 techniques.
- Why: second accepted vocabulary; ATLAS technique IDs in rule metadata make findings
  consumable by SOC/threat-intel tooling.
- Next step: map each scenario family to the closest ATLAS technique ID; emit alongside
  the ASI mapping.
- Effort: M (shares the same mapping table as 2a).
- Sources: https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release/,
  https://www.vectra.ai/topics/mitre-atlas

### 2c. CWE mappings — no agent-specific CWE taxonomy exists; use classic CWEs
- What: there is no CWE branch for agent findings. GitHub code scanning renders CWE tags
  from SARIF; the defensible mappings are CWE-441 (Unintended Proxy / Confused Deputy),
  CWE-269 (Improper Privilege Management), CWE-863 (Incorrect Authorization).
- Next step: include a `taxa` block in the SARIF `toolComponent` plus per-rule
  `relationships` so CWE tags show in the GitHub Security tab.
- Effort: S (SARIF emitter change, reuses 2a mapping table).
- Sources: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support,
  https://github.com/advanced-security/codeql-sarif-security-standard-annotator

### 2d. SARIF/JUnit expectations
- What: SARIF 2.1.0 remains the required version for GitHub code scanning in 2026;
  JUnit XML for test reporting. Nothing new mandated — current output is compliant.
  The delta is taxonomy metadata (2a–2c), not format.
- Effort: — (no action beyond 2a–2c).
- Source: https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files

## 3. Agent-security landscape check (as of 2026-07-23)

### 3a. No direct competitor found — closest 2026 work is adjacent
- "Confused-Deputy Failures in LLM Agent Frameworks" (arXiv:2606.28679, June 2026):
  audits LangChain/LlamaIndex/Stripe Agent Toolkit for per-call re-authorization and
  ships ScopeGate, a five-stage PDP/PEP gate. A defense mechanism + framework audit,
  not a delegation-chain escalation scenario testbed. Cite and differentiate:
  DelegationBench tests whether the chain *leaks authority*; ScopeGate enforces at the
  tool-call boundary.
- "Authorization Propagation in Multi-Agent AI Systems" (arXiv:2605.05440, May 2026):
  formalizes the exact invariant DelegationBench checks (authority must not accumulate
  through delegation chains). Good theory citation for the grant text.
- AgentLeak (arXiv:2602.11510): multi-agent privacy-leakage benchmark — adjacent, not
  privilege escalation.
- Uncertainty: arXiv/GitHub search is not exhaustive; re-run before submission.
- Next step: add a related-work paragraph citing these three; no code action.
- Effort: S.
- Sources: https://arxiv.org/abs/2606.28679, https://arxiv.org/html/2605.05440v1,
  https://arxiv.org/abs/2602.11510

### 3b. Open Agent Passport — delegation chains shipped
- What: OAP spec (arXiv:2603.20953, March 2026, Apache-2.0); the reference
  implementation (agent-passport-system) ships first-class `createDelegation` /
  `subDelegate` with depth and scope narrowing (per the vendor's comparison page —
  vendor source, treat as indicative). TypeScript-first.
- Why: the most credible delegation-chain spec to test *against*; an OAP-scenario pack
  ("does this delegation implementation actually narrow authority?") is a natural v0.5
  feature and a strong grant milestone.
- Next step: note in roadmap; optionally file an exploratory issue.
- Effort: S (roadmap note) / M (actual adapter, post-grant).
- Sources: https://arxiv.org/html/2603.20953v1, https://github.com/aeoess/agent-passport-system,
  https://aport.io/compare/

### 3c. Agent Threat Rules (ATR) — worth mapping to
- What: open YAML detection-rule format for agent threats
  (github.com/Agent-Threat-Rule/agent-threat-rules); has a MISP galaxy entry; rule
  ATR-2026-00074 "Cross-Agent Privilege Escalation" covers credential forwarding and
  cross-agent privilege escalation; chain-detection rules exist for malicious
  skill-chaining. Could not confirm a formally published "chain-correlation spec"
  document — the chain logic appears to live in the rule schema itself (uncertain).
- Why: DelegationBench scenarios ↔ ATR rule IDs is a bidirectional win: scenarios gain
  a detection-facing taxonomy, and ATR rules gain a test corpus.
- Next step: add `atr` IDs to the scenario mapping table alongside ASI/ATLAS (same edit).
- Effort: S–M.
- Sources: https://github.com/Agent-Threat-Rule/agent-threat-rules,
  https://agentthreatrule.org/zh/rules/ATR-2026-00074,
  https://misp-galaxy.org/agent-threat-rules/

### 3d. ROMA status — stale, unlicensed, with on-point open issues
- LICENSE: still absent. GitHub API reports `license: null`; no LICENSE file in the repo
  root listing (checked via API, 2026-07-23), despite the README claiming Apache-2.0.
- Activity: last push 2026-02-16 (~5 months stale), ~5.1k stars.
- Issues: #90 "Feature: AgentID for hierarchical meta-agent identity" (2026-03-22) and
  #92 "Integration: Governance layer for meta-agent orchestration" (2026-04-06) are both
  OPEN with zero comments — i.e., unaddressed and exactly DelegationBench's domain.
- Why: a grant reviewer from the ROMA ecosystem will know this. Positioning
  DelegationBench as the security/regression-test layer for ROMA's delegation tree —
  with a working adapter already in-tree — directly answers two of ROMA's open asks.
- Next step: reference #90/#92 explicitly in the grant narrative; consider posting a
  constructive comment on those issues linking the adapter example (do this from the
  maintainer account, not automated).
- Effort: S.
- Source: https://github.com/sentient-agi/ROMA (checked via GitHub API, 2026-07-23)

## 4. Python packaging 2026

### 4a. PEP 639 — settled, and this repo is already compliant
- What: `license = "Apache-2.0"` SPDX string + `license-files`, requires
  setuptools>=77.0.3; the TOML-table form is deprecated (builds were to hard-fail from
  2026-02-18 per setuptools' warning; some sources cite 2027-02-18 — the warning text
  evolved, treat 2026-02-18 as the operative date). `License ::` classifiers are
  forbidden alongside the SPDX form.
- Status in repo: `pyproject.toml` already uses the SPDX string, `license-files`,
  `setuptools>=77`, and has no license classifiers. No action.
- Sources: https://github.com/pypa/setuptools/issues/4903,
  https://discuss.python.org/t/expressing-project-vs-distribution-licenses-post-pep-639/90314

### 4b. PyPI name + trusted publisher setup steps
- `delegationbench` is unclaimed on PyPI (404 on 2026-07-23) — register before the
  grant goes in, so the application can link a live package.
- Setup: PyPI → Account/Project → Publishing → "Add a new pending publisher" (owner
  `sergeyizmailov`, repo `DelegationBench`, workflow `release.yml`, environment `pypi`)
  → then the workflow in 1a just works. No tokens anywhere.
- Effort: S.
- Source: https://docs.pypi.org/trusted-publishers/

### 4c. uv-based workflows
- What: `astral-sh/setup-uv` is the standard CI installer in 2026; `uv build` /
  `uv publish` support PEP 740 attestations directly (via astral-sh/attest-action when
  not using the pypa action). Using uv is optional — `python -m build` + the pypa action
  is equally current. No must-do here; do not churn the build system pre-submission.
- Effort: —.
- Source: https://github.com/astral-sh/attest-action

## 5. What a Sentient grant reviewer will look for

- Evaluation criteria (published 2026-06-24, $42M program, rolling review, non-dilutive
  grant track): technical merit, ecosystem impact, openness, long-term potential. At
  least one essential project element must be openly available — DelegationBench is
  fully Apache-2.0, which clears this trivially.
  Source: https://sentient.foundation/news/42-million-to-advance-open-source-agi
- Ecosystem impact is the weak axis to shore up: the ROMA adapter exists, so lead with
  it — a runnable "ROMA delegation tree under test" demo tied to open ROMA issues
  #90/#92 (3d) is the strongest possible reviewer hook. Effort: S (demo + writeup).
- Trust signals a reviewer checks in 30 seconds: PyPI page with verified
  links/attestations (1a/1d), Scorecard badge (1c), green CI, SECURITY.md (present),
  real tests (present). All covered above for S effort.
- Taxonomy fluency (2a/2b): an application that names ASI03/ASI07 and ATLAS techniques
  reads as current; one that invents its own vocabulary reads as pre-2026.
- Community surface: Sentient Sparks / GRID are the Foundation's community programs;
  being visibly engaged (e.g., the constructive #90/#92 comments) supports the
  "ecosystem impact" axis. Source: https://sentient.foundation/

## Suggested execution order (pre-submission)

1. Register PyPI name + Trusted Publishing + hardened `release.yml` (1a, 1b, 1d, 1e) — S.
2. OpenSSF Scorecard workflow + badge + branch protection (1c) — S.
3. ASI/ATLAS/CWE/ATR mapping table + SARIF/report emission (2a–2c, 3c) — M.
4. ROMA demo + grant narrative tied to #90/#92 (3d, 5) — S.
5. Optional: bestpractices.dev passing badge (1g), OAP adapter roadmap note (3b).

## Sources (all accessed 2026-07-23)

- https://docs.pypi.org/trusted-publishers/
- https://packaging.python.org/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/
- https://github.com/ossf/scorecard · https://scorecard.dev/
- https://tac.aswf.io/process/best_practices_badge.html
- https://github.com/slsa-framework/slsa-github-generator/blob/main/internal/builders/generic/README.md
- https://github.com/astral-sh/attest-action
- https://zenn.dev/sqer/articles/e4df3d397f5651?locale=en
- https://safedep.io/malicious-durabletask-pypi-supply-chain-attack
- https://cybelangel.com/blog/tanstack-npm-supply-chain-attack/
- https://www.threatlocker.com/blog/teampcp-supply-chain-attack-hits-tanstack
- https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files
- https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
- https://genai.owasp.org/ · https://cycode.com/blog/owasp-top-10-agentic-applications/
- https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release/ · https://www.vectra.ai/topics/mitre-atlas
- https://arxiv.org/abs/2606.28679 · https://arxiv.org/html/2605.05440v1 · https://arxiv.org/abs/2602.11510 · https://arxiv.org/html/2603.20953v1
- https://github.com/aeoess/agent-passport-system · https://aport.io/compare/
- https://github.com/Agent-Threat-Rule/agent-threat-rules · https://agentthreatrule.org/zh/rules/ATR-2026-00074 · https://misp-galaxy.org/agent-threat-rules/
- https://github.com/sentient-agi/ROMA (license/issues verified via GitHub API)
- https://github.com/pypa/setuptools/issues/4903
- https://discuss.python.org/t/expressing-project-vs-distribution-licenses-post-pep-639/90314
- https://sentient.foundation/news/42-million-to-advance-open-source-agi · https://sentient.foundation/
