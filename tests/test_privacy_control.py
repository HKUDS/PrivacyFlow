from __future__ import annotations

import json

from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import APG_UPSTREAM_SYSTEM_PROMPT, create_app
from gateway.upstream_protocol import ANTHROPIC_MESSAGES, OPENAI_RESPONSES


SECRET = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"


class RecordingUpstream:
    def __init__(self, response_body: dict | None = None, stream_chunks: list[bytes] | None = None) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.response_body = response_body or {"choices": [{"message": {"content": SECRET}}]}
        self.stream_chunks = stream_chunks or [
            f'data: {{"choices":[{{"delta":{{"content":"{SECRET}"}}}}]}}\n\n'.encode(),
            b"data: [DONE]\n\n",
        ]

    async def request_json(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return 200, {"content-type": "application/json"}, self.response_body

    async def stream_request(self, method, path, payload=None):
        self.calls.append((method, path, payload))

        async def chunks():
            for chunk in self.stream_chunks:
                yield chunk

        return 200, {"content-type": "text/event-stream"}, chunks()


def config(tmp_path, *, protocol: str = "openai_chat_completions", configured: bool = True) -> GatewayConfig:
    return GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="privacy-control-secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(
            base_url="https://upstream.example" if configured else "",
            api_key="provider-key" if configured else "",
            protocol=protocol,
        ),
    )


def disable_apg(client: TestClient) -> dict:
    response = client.put("/api/admin/privacy-control", json={"enabled": False})
    assert response.status_code == 200
    return response.json()


def test_privacy_control_bypasses_openai_request_response_stream_and_detect(tmp_path) -> None:
    upstream = RecordingUpstream()
    cfg = config(tmp_path)
    with TestClient(create_app(cfg, upstream)) as client:
        initial = client.get("/api/admin/privacy-control").json()
        assert initial["enabled"] is True
        assert initial["effective"] is True
        assert initial["available"] is True
        assert initial["active_detector_configuration_id"]

        disabled = disable_apg(client)
        assert disabled["enabled"] is False
        assert disabled["effective"] is False

        payload = {"model": "x", "messages": [{"role": "user", "content": SECRET}]}
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer local"},
            json=payload,
        )
        assert response.status_code == 200
        assert upstream.calls[0][2] == payload
        assert APG_UPSTREAM_SYSTEM_PROMPT not in json.dumps(upstream.calls[0][2])
        assert SECRET in response.text

        with client.stream(
            "POST",
            "/v1/chat/completions",
            headers={"Authorization": "Bearer local"},
            json={**payload, "stream": True},
        ) as stream_response:
            streamed = stream_response.read()
        assert stream_response.status_code == 200
        assert SECRET.encode() in streamed
        assert upstream.calls[1][2] == {**payload, "stream": True}

        detect = client.post(
            "/v1/apg/detect",
            headers={"Authorization": "Bearer local"},
            json={"text": SECRET, "return_sanitized": True},
        )
        assert detect.status_code == 200
        assert detect.json()["enabled"] is False
        assert detect.json()["findings"] == []
        assert detect.json()["diagnostics"] == []
        assert detect.json()["sanitized_text"] == SECRET

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert '"action": "disable_apg"' in audit_text
    assert '"phase": "request"' not in audit_text
    persisted = json.loads((tmp_path / "detector-control.json").read_text(encoding="utf-8"))
    assert persisted["apg_enabled"] is False


def test_privacy_control_state_persists_and_can_be_reenabled(tmp_path) -> None:
    cfg = config(tmp_path)
    with TestClient(create_app(cfg, RecordingUpstream())) as client:
        disable_apg(client)

    with TestClient(create_app(cfg, RecordingUpstream())) as client:
        restored = client.get("/api/admin/privacy-control").json()
        assert restored["enabled"] is False
        assert restored["effective"] is False
        enabled = client.put("/api/admin/privacy-control", json={"enabled": True})
        assert enabled.status_code == 200
        assert enabled.json()["effective"] is True


def test_privacy_control_requires_usable_upstream_configuration(tmp_path) -> None:
    with TestClient(create_app(config(tmp_path, configured=False), RecordingUpstream())) as client:
        status = client.get("/api/admin/privacy-control").json()
        assert status["available"] is False
        assert status["effective"] is False
        assert status["unavailable_reason"] == "no_upstream_configuration"
        assert client.put("/api/admin/privacy-control", json={"enabled": True}).status_code == 409
        assert client.put("/api/admin/privacy-control", json={"enabled": "yes"}).status_code == 400


def test_privacy_control_bypasses_responses_instructions_and_scanning(tmp_path) -> None:
    response_body = {
        "id": "resp_raw",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": SECRET}]}],
    }
    upstream = RecordingUpstream(response_body=response_body)
    with TestClient(create_app(config(tmp_path, protocol=OPENAI_RESPONSES), upstream)) as client:
        disable_apg(client)
        payload = {"model": "x", "input": SECRET, "instructions": "Keep this exact."}
        response = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer local"},
            json=payload,
        )
        assert response.status_code == 200
        assert upstream.calls[0][2] == payload
        assert APG_UPSTREAM_SYSTEM_PROMPT not in json.dumps(upstream.calls[0][2])
        assert response.json() == response_body


def test_privacy_control_bypasses_native_anthropic_system_and_scanning(tmp_path) -> None:
    response_body = {
        "id": "msg_raw",
        "type": "message",
        "role": "assistant",
        "model": "claude",
        "content": [{"type": "text", "text": SECRET}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    upstream = RecordingUpstream(response_body=response_body)
    with TestClient(create_app(config(tmp_path, protocol=ANTHROPIC_MESSAGES), upstream)) as client:
        disable_apg(client)
        payload = {
            "model": "claude",
            "max_tokens": 32,
            "system": "Keep this system prompt.",
            "messages": [{"role": "user", "content": SECRET}],
        }
        response = client.post("/v1/messages", headers={"x-api-key": "local"}, json=payload)
        assert response.status_code == 200
        assert upstream.calls[0][1] == "/v1/messages"
        assert upstream.calls[0][2] == payload
        assert APG_UPSTREAM_SYSTEM_PROMPT not in json.dumps(upstream.calls[0][2])
        assert response.json() == response_body


def test_privacy_control_bypasses_converted_anthropic_stream_scanning(tmp_path) -> None:
    upstream = RecordingUpstream()
    with TestClient(create_app(config(tmp_path), upstream)) as client:
        disable_apg(client)
        payload = {
            "model": "claude",
            "max_tokens": 32,
            "stream": True,
            "messages": [{"role": "user", "content": SECRET}],
        }
        with client.stream("POST", "/v1/messages", headers={"x-api-key": "local"}, json=payload) as response:
            body = response.read().decode("utf-8")
        assert response.status_code == 200
        sent = upstream.calls[0][2]
        assert sent["messages"] == [{"role": "user", "content": SECRET}]
        assert APG_UPSTREAM_SYSTEM_PROMPT not in json.dumps(sent)
        assert SECRET in body
        assert "event: content_block_stop" in body
