"""Tests for the network-facing real-model benchmark harness."""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

pytest.importorskip("langgraph")

MODULE_PATH = (
    Path(__file__).parents[1] / "examples" / "langgraph_real_llm_demo.py"
)
SPEC = importlib.util.spec_from_file_location("real_llm_demo", MODULE_PATH)
assert SPEC and SPEC.loader
DEMO = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DEMO
SPEC.loader.exec_module(DEMO)


class Response:
    def __init__(self, body: dict) -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.body).encode()


def test_remote_endpoint_requires_key(monkeypatch):
    monkeypatch.delenv("MISSING_BENCHMARK_KEY", raising=False)
    args = DEMO.parser().parse_args([
        "--model", "open/model",
        "--base-url", "https://models.example/v1",
        "--api-key-env", "MISSING_BENCHMARK_KEY",
    ])

    with pytest.raises(SystemExit, match="remote endpoint requires an API key"):
        asyncio.run(DEMO.main_async(args))


def test_model_retries_rate_limit_and_parses_json(monkeypatch):
    response = Response({
        "choices": [{"message": {
            "content": '{"action":"finish","args":{}}',
        }}],
    })
    attempts = iter([
        urllib.error.HTTPError(
            "https://models.example/v1/chat/completions",
            429,
            "rate limited",
            {"Retry-After": "0"},
            io.BytesIO(),
        ),
        response,
    ])

    def next_attempt(*_args, **_kwargs):
        attempt = next(attempts)
        if isinstance(attempt, Exception):
            raise attempt
        return attempt

    monkeypatch.setattr(DEMO.urllib.request, "urlopen", next_attempt)
    monkeypatch.setattr(DEMO.time, "sleep", lambda _delay: None)
    model = DEMO.OpenAICompatibleModel(
        "https://models.example/v1",
        "open/model",
        api_key="test-only",
        max_retries=1,
    )

    decision = model.decide("system", "transcript")

    assert decision.action == "finish"
    assert decision.args == {}
    assert decision.parse_error is False


def test_model_classifies_final_rate_limit(monkeypatch):
    def rate_limited(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "https://models.example/v1/chat/completions",
            429,
            "rate limited",
            {},
            io.BytesIO(),
        )

    monkeypatch.setattr(DEMO.urllib.request, "urlopen", rate_limited)
    model = DEMO.OpenAICompatibleModel(
        "https://models.example/v1",
        "open/model",
        api_key="test-only",
        max_retries=0,
    )

    with pytest.raises(DEMO.ModelEndpointError) as caught:
        model.decide("system", "transcript")

    assert caught.value.kind == "rate_limit"
