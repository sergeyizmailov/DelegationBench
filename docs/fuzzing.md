# Fuzzing

DelegationBench is fuzzed continuously with [Atheris](https://github.com/google/atheris)
(coverage-guided, libFuzzer-based) through
[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) on every pull
request and every push to `main`. Crash reproducers are uploaded as workflow
artifacts so any finding can be replayed deterministically.

## Targets

The targets live in `fuzz/` and attack the same boundaries untrusted input
crosses in production use:

| Target | Surface under test | Invariants asserted |
|---|---|---|
| `fuzz/fuzz_scenario.py` | `yaml.safe_load` + `parse_scenario` on arbitrary bytes | invalid input is rejected with `ScenarioError`, never an unexpected exception |
| `fuzz/fuzz_envelope.py` | `Envelope` construction, `derive()`, `sign()`/`verify()`, `with_principal()` | child authority ⊆ parent authority, depth increments by one, signatures verify only under their own key |
| `fuzz/fuzz_oracle.py` | `oracle.evaluate()` over fuzzed delegation graphs and tool-call sequences | never crashes on a well-typed trace; verdict kinds ⊆ V1–V7; `violation == bool(kinds)`; executed ≤ attempted |
| `fuzz/fuzz_trace.py` | `Trace` construction and `to_dict`/`to_json`/`render` serialization | JSON output round-trips exactly |

Trace-based targets build events through the same public `Trace` API the
ROMA and LangGraph adapters use, so the fuzzer explores hostile delegation
topologies (cycles, replays, re-bindings, missing principals) rather than
just malformed bytes.

Seed corpora live in `fuzz/corpora/<target>/` and include real scenario
files and real execution traces from the bundled corpus.

## Running locally

Atheris needs a clang with libFuzzer (on macOS: `brew install llvm`, then
use `/opt/homebrew/opt/llvm/bin/clang`; Apple Clang does not ship
libFuzzer):

```bash
python -m venv .venv-fuzz && . .venv-fuzz/bin/activate
CLANG_BIN=/opt/homebrew/opt/llvm/bin/clang pip install atheris  # Linux: plain pip install atheris
pip install -e .
cd fuzz
python fuzz_scenario.py corpora/fuzz_scenario -max_total_time=300
```

A crash writes a `crash-*` reproducer next to the corpus; rerun it with
`python fuzz_scenario.py <crash-file>` to reproduce. New findings that are
genuine bugs get a regression test and the minimized input joins the seed
corpus.

## CI integration

`.github/workflows/cflite.yml` builds the targets in the pinned
`gcr.io/oss-fuzz-base/base-builder-python` image (`.clusterfuzzlite/`) and
fuzzes for 300 seconds per run in `code-change` mode. The token is
read-only; the workflow only reports failures.

## OSS-Fuzz

Full [OSS-Fuzz](https://github.com/google/oss-fuzz) enrollment requires a
project to demonstrate a significant user base, which DelegationBench does
not have yet. The ClusterFuzzLite setup is intentionally OSS-Fuzz-shaped
(`project.yaml`, `Dockerfile`, `build.sh`, same target layout), so
enrollment later is a metadata PR to `google/oss-fuzz`, not a rework.
