from __future__ import annotations

import json

from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import PF_UPSTREAM_SYSTEM_PROMPT, create_app
from gateway.upstream_protocol import ANTHROPIC_MESSAGES


class FakeUpstream:
    def __init__(self) -> None:
        self.calls = []

    async def request_json(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path == "/v1/messages":
            return 200, {"content-type": "application/json"}, {
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "model": payload.get("model", "claude-test"),
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
        return 200, {"content-type": "application/json"}, {"choices": [{"message": {"content": "ok sk-proj-abcdefghijklmnopqrstuvwxyz123456"}}]}

    async def stream_request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        alias = "/workspace/project"
        if isinstance(payload, dict):
            for message in payload.get("messages", []):
                content = message.get("content") if isinstance(message, dict) else None
                if isinstance(content, str) and "repo " in content:
                    alias = content.split("repo ", 1)[1]
                    break

        async def chunks():
            yield f'data: {{"choices":[{{"delta":{{"content":"use {alias}/src/app.py"}}}}]}}\n\n'.encode()
            yield b"data: [DONE]\n\n"

        return 200, {"content-type": "text/event-stream"}, chunks()


def test_non_streaming_chat_forwards_sanitized_request(tmp_path) -> None:
    fake = FakeUpstream()
    cfg = GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(tmp_path / "audit.jsonl"), signing_secret="secret", local_api_keys={"local"}, upstream=UpstreamConfig(base_url="https://upstream", api_key="up"))
    client = TestClient(create_app(cfg, fake))
    resp = client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"model": "x", "messages": [{"role": "user", "content": "sk-proj-abcdefghijklmnopqrstuvwxyz123456"}]})
    assert resp.status_code == 200
    assert "sk-proj-" not in json.dumps(fake.calls[0][2])
    assert fake.calls[0][2]["messages"][0]["role"] == "system"
    assert PF_UPSTREAM_SYSTEM_PROMPT in fake.calls[0][2]["messages"][0]["content"]
    assert "opening `<` and closing `>` delimiters" in PF_UPSTREAM_SYSTEM_PROMPT


def test_apg_prompt_prepends_existing_system_message(tmp_path) -> None:
    fake = FakeUpstream()
    cfg = GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(tmp_path / "audit.jsonl"), signing_secret="secret", local_api_keys={"local"}, upstream=UpstreamConfig(base_url="https://upstream", api_key="up"))
    client = TestClient(create_app(cfg, fake))
    resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer local"},
        json={"model": "x", "messages": [{"role": "system", "content": "Project-specific system prompt."}, {"role": "user", "content": "hello"}]},
    )
    assert resp.status_code == 200
    messages = fake.calls[0][2]["messages"]
    assert len([m for m in messages if m.get("role") == "system"]) == 1
    assert messages[0]["content"].startswith(PF_UPSTREAM_SYSTEM_PROMPT)
    assert "Project-specific system prompt." in messages[0]["content"]


def test_apg_detect_returns_safe_dry_run_summary(tmp_path) -> None:
    fake = FakeUpstream()
    cfg = GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(tmp_path / "audit.jsonl"), signing_secret="secret", local_api_keys={"local"})
    client = TestClient(create_app(cfg, fake))
    resp = client.post(
        "/v1/apg/detect",
        headers={"Authorization": "Bearer local"},
        json={"text": "key sk-proj-abcdefghijklmnopqrstuvwxyz123456", "return_sanitized": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["findings"][0]["subtype"] == "api_key"
    assert "sk-proj-" not in body["sanitized_text"]
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz123456" not in resp.text
    assert body["diagnostics"]


def test_streaming_chat_forwards_sanitized_request(tmp_path) -> None:
    fake = FakeUpstream()
    cfg = GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(tmp_path / "audit.jsonl"), signing_secret="secret", local_api_keys={"local"}, upstream=UpstreamConfig(base_url="https://upstream", api_key="up"))
    client = TestClient(create_app(cfg, fake))
    with client.stream(
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": "Bearer local"},
        json={"stream": True, "model": "x", "messages": [{"role": "user", "content": "sk-proj-abcdefghijklmnopqrstuvwxyz123456"}]},
    ) as resp:
        body = resp.read()
    assert resp.status_code == 200
    assert b"data:" in body
    assert "sk-proj-" not in json.dumps(fake.calls[0][2])


def test_streaming_response_materializes_path_alias_for_local_agent(tmp_path) -> None:
    fake = FakeUpstream()
    cfg = GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(tmp_path / "audit.jsonl"), signing_secret="secret", local_api_keys={"local"}, upstream=UpstreamConfig(base_url="https://upstream", api_key="up"))
    client = TestClient(create_app(cfg, fake))
    with client.stream(
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": "Bearer local"},
        json={"stream": True, "model": "x", "messages": [{"role": "user", "content": "repo /Users/howard/private/project"}]},
    ) as resp:
        body = resp.read().decode("utf-8")
    assert resp.status_code == 200
    assert "/workspace/project" not in body
    assert "/Users/howard/private/project/src/app.py" in body


def test_model_response_is_scanned_before_return(tmp_path) -> None:
    fake = FakeUpstream()
    cfg = GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(tmp_path / "audit.jsonl"), signing_secret="secret", local_api_keys={"local"})
    client = TestClient(create_app(cfg, fake))
    resp = client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"messages": [{"content": "hello"}]})
    assert "sk-proj-" not in resp.text


def test_anthropic_messages_forwards_sanitized_request(tmp_path) -> None:
    fake = FakeUpstream()
    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(
            base_url="https://upstream",
            api_key="up",
            protocol=ANTHROPIC_MESSAGES,
        ),
    )
    client = TestClient(create_app(cfg, fake))
    resp = client.post(
        "/v1/messages",
        headers={"x-api-key": "local"},
        json={
            "model": "claude-sonnet-4-5-20250929",
            "max_tokens": 128,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "debug sk-proj-abcdefghijklmnopqrstuvwxyz123456"}]}],
            "tools": [{"name": "Read", "description": "read files", "input_schema": {"type": "object", "properties": {"file_path": {"type": "string"}}}}],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["type"] == "message"
    assert fake.calls[0][1] == "/v1/messages"
    assert fake.calls[0][2]["model"] == "claude-sonnet-4-5-20250929"
    assert "sk-proj-" not in json.dumps(fake.calls[0][2])
    assert PF_UPSTREAM_SYSTEM_PROMPT in fake.calls[0][2]["system"]


def test_invalid_upstream_errors_handled_safely(tmp_path) -> None:
    class ErrorUpstream:
        async def request_json(self, method, path, payload=None):
            return 500, {"content-type": "application/json"}, {"error": {"message": "upstream failed"}}

    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(api_key="provider-key"),
    )
    client = TestClient(create_app(cfg, ErrorUpstream()))
    resp = client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"messages": [{"content": "hello"}]})
    assert resp.status_code == 500
    assert "upstream failed" in resp.text


def test_audit_event_created_for_every_request(tmp_path) -> None:
    fake = FakeUpstream()
    audit = tmp_path / "audit.jsonl"
    cfg = GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(audit), signing_secret="secret", local_api_keys={"local"}, upstream=UpstreamConfig(api_key="provider-key"))
    client = TestClient(create_app(cfg, fake))
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"messages": [{"content": "hello"}]})
    lines = audit.read_text().splitlines()
    assert len(lines) >= 2


def test_local_dummy_api_key_maps_to_gateway_session(tmp_path) -> None:
    fake = FakeUpstream()
    audit = tmp_path / "audit.jsonl"
    cfg = GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(audit), signing_secret="secret", local_api_keys={"local"}, upstream=UpstreamConfig(api_key="provider-key"))
    client = TestClient(create_app(cfg, fake))
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"messages": [{"content": "hello"}]})
    assert "sess_" in audit.read_text()
