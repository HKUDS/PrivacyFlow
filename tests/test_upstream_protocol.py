from __future__ import annotations

import asyncio
import json
import re

import httpx
from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.placeholder_parser import PLACEHOLDER_RE
from gateway.server import create_app
from gateway.upstream_client import UpstreamClient
from gateway.upstream_protocol import (
    ANTHROPIC_MESSAGES,
    OPENAI_CHAT_COMPLETIONS,
    OPENAI_RESPONSES,
)


def test_upstream_client_forwards_native_anthropic_payload_and_response() -> None:
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "model": "claude-test",
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )

    client = UpstreamClient(
        UpstreamConfig(
            base_url="https://provider.example/anthropic",
            api_key="provider-key",
            protocol=ANTHROPIC_MESSAGES,
        ),
        transport=httpx.MockTransport(handler),
    )
    status, _, body = asyncio.run(
        client.request_json(
            "POST",
            "/v1/messages",
            {
                "model": "claude-test",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
            },
        )
    )

    assert status == 200
    assert captured["url"] == "https://provider.example/anthropic/v1/messages"
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["x-api-key"] == "provider-key"
    assert headers["anthropic-version"] == "2023-06-01"
    assert "authorization" not in headers
    assert captured["body"]["messages"] == [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
    assert body["type"] == "message"
    assert body["content"] == [{"type": "text", "text": "ok"}]


class _FormatRecordingUpstream:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def request_json(self, method, path, payload=None):
        self.calls.append(path)
        if path == "/v1/responses":
            return 200, {"content-type": "application/json"}, {
                "id": "resp_1",
                "object": "response",
                "status": "completed",
                "output": [],
            }
        if path == "/v1/messages":
            return 200, {"content-type": "application/json"}, {
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "claude-test",
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }
        return 200, {"content-type": "application/json"}, {
            "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]
        }


def test_openai_responses_format_only_accepts_responses_endpoint(tmp_path) -> None:
    upstream = _FormatRecordingUpstream()
    config = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="test-signing-secret",
        local_api_keys={"agent-key"},
        strict_mode=True,
        upstream=UpstreamConfig(
            base_url="https://provider.example/v1",
            api_key="provider-key",
            protocol=OPENAI_RESPONSES,
        ),
    )
    headers = {"Authorization": "Bearer agent-key"}

    with TestClient(create_app(config, upstream)) as client:
        responses = client.post(
            "/v1/responses",
            headers=headers,
            json={"model": "gpt-test", "input": "hello"},
        )
        assert responses.status_code == 200

        chat = client.post(
            "/v1/chat/completions",
            headers=headers,
            json={"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert chat.status_code == 501
        assert chat.json()["error"]["code"] == "APG_UPSTREAM_PROTOCOL_UNSUPPORTED"

        messages = client.post(
            "/v1/messages",
            headers=headers,
            json={"model": "claude-test", "max_tokens": 64, "messages": [{"role": "user", "content": "hello"}]},
        )
        assert messages.status_code == 501
        assert messages.json()["type"] == "error"

    assert upstream.calls == ["/v1/responses"]


def test_openai_chat_completions_format_only_accepts_chat_endpoint(tmp_path) -> None:
    upstream = _FormatRecordingUpstream()
    config = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="test-signing-secret",
        local_api_keys={"agent-key"},
        strict_mode=True,
        upstream=UpstreamConfig(
            base_url="https://provider.example/v1",
            api_key="provider-key",
            protocol=OPENAI_CHAT_COMPLETIONS,
        ),
    )

    with TestClient(create_app(config, upstream)) as client:
        chat = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert chat.status_code == 200

        responses = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "gpt-test", "input": "hello"},
        )
        assert responses.status_code == 501
        assert responses.json()["error"]["code"] == "APG_UPSTREAM_PROTOCOL_UNSUPPORTED"

        messages = client.post(
            "/v1/messages",
            headers={"x-api-key": "agent-key"},
            json={"model": "claude-test", "max_tokens": 64, "messages": [{"role": "user", "content": "hello"}]},
        )
        assert messages.status_code == 501
        assert messages.json()["type"] == "error"

    assert upstream.calls == ["/v1/chat/completions"]


def test_anthropic_messages_format_only_accepts_messages_endpoint(tmp_path) -> None:
    upstream = _FormatRecordingUpstream()
    config = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="test-signing-secret",
        local_api_keys={"agent-key"},
        strict_mode=True,
        upstream=UpstreamConfig(
            base_url="https://provider.example/anthropic",
            api_key="provider-key",
            protocol=ANTHROPIC_MESSAGES,
        ),
    )

    with TestClient(create_app(config, upstream)) as client:
        messages = client.post(
            "/v1/messages",
            headers={"x-api-key": "agent-key"},
            json={"model": "claude-test", "max_tokens": 64, "messages": [{"role": "user", "content": "hello"}]},
        )
        assert messages.status_code == 200
        assert messages.json()["type"] == "message"

        chat = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert chat.status_code == 501
        assert chat.json()["error"]["code"] == "APG_UPSTREAM_PROTOCOL_UNSUPPORTED"

        responses = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "gpt-test", "input": "hello"},
        )
        assert responses.status_code == 501
        assert responses.json()["error"]["code"] == "APG_UPSTREAM_PROTOCOL_UNSUPPORTED"

    assert upstream.calls == ["/v1/messages"]


class _ChunkStream(httpx.AsyncByteStream):
    def __init__(self, content: bytes, size: int = 9) -> None:
        self.content = content
        self.size = size

    async def __aiter__(self):
        for index in range(0, len(self.content), self.size):
            yield self.content[index : index + self.size]


def test_anthropic_agent_materializes_tools_through_native_anthropic_upstream(tmp_path) -> None:
    raw_secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    upstream_payloads: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        upstream_payloads.append(payload)
        message_payload = json.dumps(payload.get("messages", []))
        match = re.search(r"<APG:v1:secret:[^>]+>", message_payload)
        assert match is not None
        placeholder = match.group(0)
        if payload.get("stream"):
            argument_json = json.dumps({"token": placeholder})
            events = [
                {"type": "message_start", "message": {"id": "msg_stream", "model": payload["model"], "usage": {"input_tokens": 8}}},
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "tool_use", "id": "toolu_stream", "name": "validate", "input": {}},
                },
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": argument_json[:11]},
                },
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": argument_json[11:]},
                },
                {"type": "content_block_stop", "index": 0},
                {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 5}},
                {"type": "message_stop"},
            ]
            content = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events).encode()
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=_ChunkStream(content))
        return httpx.Response(
            200,
            json={
                "id": "msg_nonstream",
                "type": "message",
                "role": "assistant",
                "model": payload["model"],
                "content": [{"type": "tool_use", "id": "toolu_1", "name": "validate", "input": {"token": placeholder}}],
                "stop_reason": "tool_use",
                "stop_sequence": "END",
                "usage": {"input_tokens": 8, "output_tokens": 5},
            },
        )

    upstream = UpstreamClient(
        UpstreamConfig(
            base_url="https://provider.example/anthropic",
            api_key="provider-key",
            protocol=ANTHROPIC_MESSAGES,
        ),
        transport=httpx.MockTransport(handler),
    )
    config = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="test-signing-secret",
        local_api_keys={"agent-key"},
        strict_mode=True,
        upstream=upstream.config,
    )
    headers = {"Authorization": "Bearer agent-key"}

    with TestClient(create_app(config, upstream)) as client:
        unsupported_responses = client.post(
            "/v1/responses",
            headers=headers,
            json={"model": "claude-test", "input": "hello"},
        )
        assert unsupported_responses.status_code == 501
        assert unsupported_responses.json()["error"]["code"] == "APG_UPSTREAM_PROTOCOL_UNSUPPORTED"

        unsupported_chat = client.post(
            "/v1/chat/completions",
            headers=headers,
            json={
                "model": "claude-test",
                "messages": [{"role": "user", "content": f"Validate {raw_secret}"}],
            },
        )
        assert unsupported_chat.status_code == 501
        assert unsupported_chat.json()["error"]["code"] == "APG_UPSTREAM_PROTOCOL_UNSUPPORTED"

        anthropic_response = client.post(
            "/v1/messages",
            headers={**headers, "anthropic-version": "2023-06-01"},
            json={
                "model": "claude-test",
                "max_tokens": 256,
                "system": [
                    {
                        "type": "text",
                        "text": "Keep the native Anthropic system block.",
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                "metadata": {"user_id": "42"},
                "thinking": {"type": "enabled", "budget_tokens": 128},
                "messages": [{"role": "user", "content": f"Validate {raw_secret}"}],
            },
        )
        assert anthropic_response.status_code == 200
        assert anthropic_response.json()["content"][0]["input"]["token"] == raw_secret
        assert anthropic_response.json()["stop_sequence"] == "END"

        anthropic_stream = client.post(
            "/v1/messages",
            headers={**headers, "anthropic-version": "2023-06-01"},
            json={
                "model": "claude-test",
                "max_tokens": 256,
                "stream": True,
                "messages": [{"role": "user", "content": f"Validate {raw_secret}"}],
            },
        )
        assert anthropic_stream.status_code == 200
        assert raw_secret in anthropic_stream.text
        assert "<APG:v1:secret:" not in anthropic_stream.text
        assert "msg_stream" in anthropic_stream.text
        assert "event: message_stop" in anthropic_stream.text

    assert len(upstream_payloads) == 2
    assert all(raw_secret not in json.dumps(payload) for payload in upstream_payloads)
    assert all("<APG:v1:secret:" in json.dumps(payload) for payload in upstream_payloads)
    native_payload = upstream_payloads[0]
    assert native_payload["metadata"] == {"user_id": "42"}
    assert native_payload["thinking"] == {"type": "enabled", "budget_tokens": 128}
    assert native_payload["system"][1] == {
        "type": "text",
        "text": "Keep the native Anthropic system block.",
        "cache_control": {"type": "ephemeral"},
    }


def test_native_anthropic_visible_text_restores_exact_placeholder(tmp_path) -> None:
    raw_secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"

    class NativeAnthropicEcho:
        config = UpstreamConfig(
            base_url="https://provider.example/anthropic",
            api_key="provider-key",
            protocol=ANTHROPIC_MESSAGES,
        )

        async def request_json(self, method, path, payload=None):
            assert path == "/v1/messages"
            match = PLACEHOLDER_RE.search(json.dumps(payload))
            assert match is not None
            return (
                200,
                {"content-type": "application/json"},
                {
                    "id": "msg_visible",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-test",
                    "content": [{"type": "text", "text": f'OPENAI_API_KEY = "{match.group(0)}"'}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 8, "output_tokens": 8},
                },
            )

        async def stream_request(self, method, path, payload=None):
            raise NotImplementedError

    config = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="test-signing-secret",
        local_api_keys={"agent-key"},
        upstream=NativeAnthropicEcho.config,
    )
    client = TestClient(create_app(config, NativeAnthropicEcho()))

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": "agent-key"},
        json={
            "model": "claude-test",
            "max_tokens": 128,
            "messages": [{"role": "user", "content": f"Show the assignment for {raw_secret}"}],
        },
    )

    assert response.status_code == 200
    assert response.json()["content"][0]["text"] == f'OPENAI_API_KEY = "{raw_secret}"'
    assert "<APG:v1:" not in response.text
    audit = (tmp_path / "audit.jsonl").read_text()
    assert '"sink": "local_user"' in audit
    assert raw_secret not in audit
