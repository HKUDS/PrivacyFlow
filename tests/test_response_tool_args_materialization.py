from __future__ import annotations

import json

from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import create_app


class FakeUpstream:
    def __init__(self, response_body: dict | None = None) -> None:
        self.calls = []
        self.response_body = response_body or {}

    async def request_json(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return 200, {"content-type": "application/json"}, self.response_body

    async def stream_request(self, method, path, payload=None):
        raise NotImplementedError


def _cfg(tmp_path):
    return GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(base_url="https://upstream", api_key="up"),
    )


def _request_round_trip(client: TestClient) -> str:
    return client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer local"},
        json={"model": "x", "messages": [{"role": "user", "content": "use my API key sk-proj-abcdefghijklmnopqrstuvwxyz0"}]},
    )


def test_secret_in_tool_call_arguments_materialized_to_raw_value(tmp_path) -> None:
    # First request: redact a real secret so APG registers a signed placeholder.
    # Then we craft a fake tool_call response that echoes the same placeholder
    # back inside arguments; the downlink must restore the raw secret there.
    fake = FakeUpstream()
    client = TestClient(create_app(_cfg(tmp_path), fake))

    # First call: capture the placeholder that APG substituted upstream.
    resp1 = _request_round_trip(client)
    assert resp1.status_code == 200
    upstream_payload = fake.calls[0][2]
    placeholder = _extract_first_placeholder(json.dumps(upstream_payload))
    assert placeholder is not None, "expected a signed APG placeholder upstream"
    assert "sk-proj-" not in json.dumps(upstream_payload), "raw secret leaked upstream"

    # Second call: upstream returns a tool_call whose arguments field holds the
    # placeholder. The response scanner must materialize it back to the raw
    # secret so the harness can execute the tool with the real credential.
    fake.response_body = {
        "choices": [
            {
                "message": {
                    "content": "Calling the API now with " + placeholder,
                    "tool_calls": [
                        {
                            "id": "call_01",
                            "type": "function",
                            "function": {
                                "name": "openai_chat",
                                "arguments": json.dumps({"api_key": placeholder, "prompt": "hi"}),
                            },
                        }
                    ],
                }
            }
        ]
    }
    resp2 = _request_round_trip(client)
    body = resp2.json()
    tool_args = body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    materialized = json.loads(tool_args)
    assert materialized["api_key"] == "sk-proj-abcdefghijklmnopqrstuvwxyz0", "tool_call args must contain the raw secret"
    content = body["choices"][0]["message"]["content"]
    assert "sk-proj-" not in content, "visible content must stay redacted"
    assert "<APG:v1:" in content, "visible content keeps a redaction marker"


def test_forged_placeholder_inside_tool_call_args_is_left_intact(tmp_path) -> None:
    fake = FakeUpstream(
        response_body={
            "choices": [
                {
                    "message": {
                        "content": "ok",
                        "tool_calls": [
                            {
                                "id": "call_01",
                                "type": "function",
                                "function": {
                                    "name": "x",
                                    "arguments": json.dumps({"api_key": "<APG:v1:secret:secr_bogus:sess_bogus:1:AAAAAAAAAAAAAAAAAAAA>"}),
                                },
                            }
                        ],
                    }
                }
            ]
        }
    )
    client = TestClient(create_app(_cfg(tmp_path), fake))
    resp = _request_round_trip(client)
    body = resp.json()
    args = json.loads(body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])
    assert args["api_key"].startswith("<APG:v1:secret:"), "invalid placeholder must fail-closed (retained as-is)"


def _extract_first_placeholder(text: str) -> str | None:
    import re

    m = re.search(r"<APG:v1:[^>]+>", text)
    return m.group(0) if m else None