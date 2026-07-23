# Reproducible benchmark reports

This directory is reserved for reviewed, versioned real-model results.
DelegationBench does not publish smoke-test output as benchmark evidence.

Generate a candidate report with:

```bash
python examples/langgraph_real_llm_demo.py \
  --model MODEL_ID \
  --base-url http://127.0.0.1:8080/v1 \
  --model-revision WEIGHT_REVISION \
  --server-name SERVER_NAME \
  --server-version SERVER_VERSION \
  --hardware "HARDWARE DESCRIPTION" \
  --seed 7 \
  --runs 10 \
  --output benchmarks/results/MODEL_SLUG.json
```

Before committing a result, verify the evidence checklist in
[docs/grant-readiness.md](../docs/grant-readiness.md), including exact model and
server versions, hardware, configuration, repeated attack and benign trials,
errors, aggregate rates, and per-run traces.

The harness continues after an individual endpoint failure, records the error
in the per-run artifact, and exits non-zero after writing the report. Private
endpoint URLs and API keys are not written to the report.

No result file in this directory should contain API keys, private endpoint
URLs, usernames, or other machine-specific secrets.
