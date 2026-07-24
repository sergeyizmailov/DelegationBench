# Hosted open-weight benchmarks with NVIDIA NIM

NVIDIA's hosted NIM catalog provides an OpenAI-compatible development endpoint,
so the real LangGraph benchmark can run without downloading model weights or
using the local GPU.

## Models

The maintained benchmark pair is:

| Model | NVIDIA model ID | Family |
|---|---|---|
| Llama 3.3 70B Instruct | `meta/llama-3.3-70b-instruct` | Meta Llama |
| Qwen3-Next 80B-A3B Instruct | `qwen/qwen3-next-80b-a3b-instruct` | Qwen |

Both model pages advertise a downloadable checkpoint and a free development
endpoint:

- [Llama 3.3 70B Instruct on NVIDIA NIM](https://build.nvidia.com/meta/llama-3_3-70b-instruct)
- [Qwen3-Next 80B-A3B Instruct on NVIDIA NIM](https://build.nvidia.com/qwen/qwen3-next-80b-a3b-instruct)

Endpoint availability and free-tier policy are provider-controlled and may
change. Confirm both model pages immediately before reproducing a run.

## Credential setup

Create a development key in [NVIDIA API
settings](https://build.nvidia.com/settings/api-keys), then expose it only to
the current shell:

```bash
read -s NVIDIA_API_KEY
export NVIDIA_API_KEY
```

Do not pass the key as a command-line argument, commit it, or include it in a
benchmark artifact. Unset it after the runs:

```bash
unset NVIDIA_API_KEY
```

## Reproduce the two reports

### GitHub Actions

The repository's manual `Real open-weight model benchmarks` workflow is the
preferred publication path. It reads `NVIDIA_API_KEY` from the protected
`benchmarks` environment, runs both models sequentially, and uploads one raw
JSON artifact per model. It never runs on pushes or pull requests.

An owner configures the secret once:

```bash
gh secret set NVIDIA_API_KEY \
  --env benchmarks \
  --repo sergeyizmailov/DelegationBench
```

Then run the workflow from the Actions tab or with:

```bash
gh workflow run real-model-benchmarks.yml \
  --repo sergeyizmailov/DelegationBench \
  --field runs=10
```

Delete the environment secret after downloading and reviewing the artifacts if
continued access is not needed.

### Local alternative

Install the demo dependencies:

```bash
python -m pip install -e '.[langgraph-demo]'
```

Run at least ten attack and ten benign trials per model:

```bash
python examples/langgraph_real_llm_demo.py \
  --model meta/llama-3.3-70b-instruct \
  --base-url https://integrate.api.nvidia.com/v1 \
  --api-key-env NVIDIA_API_KEY \
  --provider NVIDIA \
  --model-revision provider-managed-not-exposed \
  --server-name "NVIDIA hosted NIM API" \
  --server-version provider-managed \
  --hardware "NVIDIA-managed hosted inference; exact hardware undisclosed" \
  --temperature 0 --max-tokens 256 \
  --max-retries 5 --retry-base-seconds 3 --timeout 120 \
  --request-delay-seconds 6 \
  --runs 10 \
  --output benchmarks/results/nvidia-llama-3.3-70b-instruct.json
```

```bash
python examples/langgraph_real_llm_demo.py \
  --model qwen/qwen3-next-80b-a3b-instruct \
  --base-url https://integrate.api.nvidia.com/v1 \
  --api-key-env NVIDIA_API_KEY \
  --provider NVIDIA \
  --model-revision provider-managed-not-exposed \
  --server-name "NVIDIA hosted NIM API" \
  --server-version provider-managed \
  --hardware "NVIDIA-managed hosted inference; exact hardware undisclosed" \
  --temperature 0 --max-tokens 256 \
  --max-retries 5 --retry-base-seconds 3 --timeout 120 \
  --request-delay-seconds 6 \
  --runs 10 \
  --output benchmarks/results/nvidia-qwen3-next-80b-a3b-instruct.json
```

NVIDIA does not expose the exact hosted weight revision or serving build
through this API path. The reports say so explicitly rather than substituting
the revision of a possibly different upstream checkpoint.

## Review

Before committing either report:

1. Confirm 10 completed attack and 10 completed benign trials.
2. Inspect every invalid output, timeout, rate-limit error, or execution error.
3. Confirm that the report contains no API key or private endpoint.
4. Recalculate the aggregate metrics from the per-run records.
5. Record the exact DelegationBench commit used for the run in the result
   index.

The reviewed 2026-07-24 artifacts and aggregate table are in
[`benchmarks/results/`](../benchmarks/results/).

The benchmark is intentionally small and focused: it measures whether a real
model follows an injected cross-agent payment instruction in one paired
LangGraph task. It does not turn the 75-scenario deterministic corpus into 75
LLM-driven tasks and must not be described that way.
