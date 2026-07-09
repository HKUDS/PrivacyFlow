from __future__ import annotations

import json

from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import create_app


class FakeUpstream:
    def __init__(self) -> None:
        self.calls = []

    async def request_json(self, method, path, payload=None):
        raise NotImplementedError

    async def stream_request(self, method, path, payload=None):
        self.calls.append((method, path, payload))

        async def chunks():
            # Model echoes the canary secret inside a single SSE delta.
            yield b'data: {"choices":[{"delta":{"content":"here is the key sk-proj-abcdefghijklmnopqrstuvwxyz0"}}]}\n\n'
            yield b"data: [DONE]\n\n"

        return 200, {"content-type": "text/event-stream"}, chunks()


def _cfg(tmp_path):
    return GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(base_url="https://upstream", api_key="up"),
    )


def test_streaming_response_redacts_model_echoed_secret(tmp_path) -> None:
    fake = FakeUpstream()
    client = TestClient(create_app(_cfg(tmp_path), fake))
    with client.stream(
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": "Bearer local"},
        json={"model": "x", "stream": True, "messages": [{"role": "user", "content": "echo my key sk-proj-abcdefghijklmnopqrstuvwxyz0"}]},
    ) as resp:
        body = resp.read().decode("utf-8")
    # The upstream must have received only placeholders, never the raw canary.
    upstream_payload = fake.calls[0][2]
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz0" not in json.dumps(upstream_payload)
    # The streamed-down content must not contain the raw secret echo split
    # across chunks; it should be replaced with an APG redaction marker.
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz" not in body, "raw secret must not survive stream scan"
    assert "<APG:v1:" in body or "<APG_DETECTED" in body, "stream scan should leave an APG marker"