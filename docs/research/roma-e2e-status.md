# ROMA End-to-End Status

This note records exactly where the ROMA end-to-end demonstration stands, what
blocks a live run, and the proposed path — per the pre-submission review's
Priority 2.

## What exists today

- `src/delegationbench/adapters/roma.py` — the ROMA adapter (clean-room,
  import-only; ROMA's licensing is unresolved, see
  [roma-integration.md](roma-integration.md) §10).
- `examples/roma_adapter_example.py` — a complete end-to-end script: limited
  user grant (read-only), a real `RecursiveSolver` run, delegation edges
  reconstructed from ROMA's task DAG, tool calls captured through the dspy
  callback, and a deterministic oracle verdict. The script documents which
  gaps the adapter compensates for (no task ids on ROMA tool records, no
  module-level execution events).
- Synthetic unit tests for the adapter (`tests/test_roma_adapter.py`).

## What blocks a live recorded run

1. **An LM endpoint.** ROMA (via dspy/LiteLLM) needs a configured model
   (`OPENAI_API_KEY` or compatible). The development keys used for the
   NVIDIA-hosted benchmarks were rotated out after those runs; no key is
   stored in this repository. Running the example end-to-end is a one-command
   step for anyone with a key:

   ```bash
   pip install "roma-dspy @ git+https://github.com/sentient-agi/ROMA.git@a6e3bb4"
   OPENAI_API_KEY=... python examples/roma_adapter_example.py
   ```

2. **License clarity.** ROMA's README references Apache 2.0 but the repository
   has no LICENSE file at the audited commit `a6e3bb4`. Until clarified, the
   adapter stays import-only and ROMA is never vendored or installed by
   DelegationBench itself. A license clarification request to the ROMA
   maintainers is part of the outreach kit (`docs/validation-kit.md`).

## Proposed fixes (for ROMA upstream)

These would let the adapter drop its compensation logic:

1. Attach the ROMA task id to tool-call records (removes stack-based
   correlation and the "uncorrelated" V5 fallback).
2. Emit the already-defined module-level execution events (removes post-hoc
   DAG reconstruction).
3. Propagate run metadata (at minimum a caller-supplied principal) into
   subtask execution (removes side-channel principal injection).

## Honest claim level

The ROMA adapter is **experimental**: validated against synthetic fixtures and
reviewed ROMA source, not yet against a live ROMA run. This is stated wherever
ROMA support is mentioned; do not upgrade the claim until a recorded live run
exists.
