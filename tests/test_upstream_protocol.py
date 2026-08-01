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
    DEFAULT_UPSTREAM_PROTOCOLS,
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
            headers={
                "x-request-id": "req_safe_123",
                "set-cookie": "private-cookie=secret",
            },
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
    status, response_headers, body = asyncio.run(
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
    assert response_headers["x-request-id"] == "req_safe_123"
    assert "set-cookie" not in response_headers
    assert captured["url"] == "https://provider.example/anthropic/v1/messages"
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["x-api-key"] == "provider-key"
    assert headers["anthropic-version"] == "2023-06-01"
    assert "authorization" not in headers
    assert captured["body"]["messages"] == [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
    assert body["type"] == "message"
    assert body["content"] == [{"type": "text", "text": "ok"}]


def test_upstream_client_resolves_api_root_and_full_endpoint_urls() -> None:
    root_client = UpstreamClient(
        UpstreamConfig(
            base_url="https://openrouter.ai/api/v1",
            api_key="provider-key",
            protocol=OPENAI_CHAT_COMPLETIONS,
            strip_local_v1=True,
        )
    )
    assert root_client.resolve_upstream_url("/chat/completions") == "https://openrouter.ai/api/v1/chat/completions"
    assert root_client.resolve_upstream_url("/models") == "https://openrouter.ai/api/v1/models"

    endpoint_client = UpstreamClient(
        UpstreamConfig(
            base_url="https://openrouter.ai/api/v1/chat/completions",
            api_key="provider-key",
            protocol=OPENAI_CHAT_COMPLETIONS,
            strip_local_v1=True,
        )
    )
    assert endpoint_client.resolve_upstream_url("/chat/completions") == "https://openrouter.ai/api/v1/chat/completions"
    assert endpoint_client.resolve_upstream_url("/v1/models") == "https://openrouter.ai/api/v1/models"


def test_upstream_client_selects_native_auth_and_endpoint_override_from_request_path() -> None:
    captured: list[tuple[str, dict[str, str]]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append((str(request.url), dict(request.headers)))
        return httpx.Response(200, json={"ok": True})

    client = UpstreamClient(
        UpstreamConfig(
            base_url="https://provider.example/v1",
            api_key="provider-key",
            protocol=OPENAI_CHAT_COMPLETIONS,
            endpoint_overrides={ANTHROPIC_MESSAGES: "https://anthropic.example/custom/messages"},
        ),
        transport=httpx.MockTransport(handler),
    )
    asyncio.run(client.request_json("POST", "/v1/responses", {"model": "gpt-test"}))
    asyncio.run(client.request_json("POST", "/v1/messages", {"model": "claude-test"}))

    assert captured[0][0] == "https://provider.example/v1/responses"
    assert captured[0][1]["authorization"] == "Bearer provider-key"
    assert "x-api-key" not in captured[0][1]
    assert captured[1][0] == "https://anthropic.example/custom/messages"
    assert captured[1][1]["x-api-key"] == "provider-key"
    assert "authorization" not in captured[1][1]


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


def test_responses_primary_profile_exposes_all_native_endpoints(tmp_path) -> None:
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
        assert chat.status_code == 200

        messages = client.post(
            "/v1/messages",
            headers=headers,
            json={"model": "claude-test", "max_tokens": 64, "messages": [{"role": "user", "content": "hello"}]},
        )
        assert messages.status_code == 200

    assert upstream.calls == ["/v1/responses", "/v1/chat/completions", "/v1/messages"]


def test_chat_primary_profile_exposes_all_native_endpoints(tmp_path) -> None:
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
        assert responses.status_code == 200

        messages = client.post(
            "/v1/messages",
            headers={"x-api-key": "agent-key"},
            json={"model": "claude-test", "max_tokens": 64, "messages": [{"role": "user", "content": "hello"}]},
        )
        assert messages.status_code == 200

    assert upstream.calls == ["/v1/chat/completions", "/v1/responses", "/v1/messages"]


def test_upstream_profile_defaults_to_all_native_formats(tmp_path) -> None:
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
    headers = {"Authorization": "Bearer agent-key"}

    with TestClient(create_app(config, upstream)) as client:
        configured = client.put(
            "/api/admin/upstream-configuration",
            json={
                "profile_id": "runtime_default",
                "name": "Multi format",
                "base_url": "https://provider.example/v1",
                "api_key": "",
            },
        )
        assert configured.status_code == 200
        assert configured.json()["protocols"] == list(DEFAULT_UPSTREAM_PROTOCOLS)

        assert client.post(
            "/v1/chat/completions",
            headers=headers,
            json={"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]},
        ).status_code == 200
        assert client.post(
            "/v1/responses",
            headers=headers,
            json={"model": "gpt-test", "input": "hello"},
        ).status_code == 200
        assert client.post(
            "/v1/messages",
            headers={"x-api-key": "agent-key"},
            json={"model": "claude-test", "max_tokens": 64, "messages": [{"role": "user", "content": "hello"}]},
        ).status_code == 200

    assert upstream.calls == ["/v1/chat/completions", "/v1/responses", "/v1/messages"]


def test_unsupported_native_format_returns_actual_upstream_error(tmp_path) -> None:
    class UnsupportedResponsesUpstream:
        async def request_json(self, method, path, payload=None):
            assert path == "/v1/responses"
            return 404, {"content-type": "application/json"}, {
                "error": {
                    "code": "route_not_found",
                    "message": "This provider does not implement the Responses endpoint.",
                }
            }

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

    with TestClient(create_app(config, UnsupportedResponsesUpstream())) as client:
        response = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "gpt-test", "input": "hello"},
        )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "route_not_found"


def test_anthropic_primary_profile_exposes_all_native_endpoints(tmp_path) -> None:
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
        assert chat.status_code == 200

        responses = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "gpt-test", "input": "hello"},
        )
        assert responses.status_code == 200

    assert upstream.calls == ["/v1/messages", "/v1/chat/completions", "/v1/responses"]


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
