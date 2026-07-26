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
    anthropic_message_to_openai,
    anthropic_stream_to_openai,
    openai_chat_to_anthropic,
)


def test_openai_chat_request_converts_tools_and_results_to_anthropic() -> None:
    converted = openai_chat_to_anthropic(
        {
            "model": "claude-test",
            "max_tokens": 512,
            "stream": True,
            "stop": "END",
            "messages": [
                {"role": "system", "content": "Keep secrets local."},
                {"role": "developer", "content": "Use structured tools."},
                {"role": "user", "content": "Validate the credential."},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "validate", "arguments": '{"token":"<APG:v1:secret:...>"}'},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "validate",
                        "description": "Validate locally",
                        "parameters": {"type": "object", "properties": {"token": {"type": "string"}}},
                    },
                }
            ],
            "tool_choice": {"type": "function", "function": {"name": "validate"}},
        }
    )

    assert converted["system"] == "Keep secrets local.\n\nUse structured tools."
    assert converted["stream"] is True
    assert converted["stop_sequences"] == ["END"]
    assert converted["tools"][0]["input_schema"]["properties"]["token"]["type"] == "string"
    assert converted["tool_choice"] == {"type": "tool", "name": "validate"}
    tool_use = converted["messages"][1]["content"][0]
    assert tool_use == {
        "type": "tool_use",
        "id": "call_1",
        "name": "validate",
        "input": {"token": "<APG:v1:secret:...>"},
    }
    assert converted["messages"][2]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "call_1",
        "content": "ok",
    }

    no_tools = openai_chat_to_anthropic(
        {
            "model": "claude-test",
            "messages": [{"role": "user", "content": "Do not call tools."}],
            "tools": converted["tools"],
            "tool_choice": "none",
        }
    )
    assert "tools" not in no_tools
    assert "tool_choice" not in no_tools


def test_anthropic_message_converts_text_tool_calls_and_usage_to_openai() -> None:
    converted = anthropic_message_to_openai(
        {
            "id": "msg_1",
            "type": "message",
            "model": "claude-test",
            "content": [
                {"type": "text", "text": "Running locally."},
                {"type": "tool_use", "id": "toolu_1", "name": "validate", "input": {"token": "<APG:v1:secret:...>"}},
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 12, "output_tokens": 7},
        }
    )

    assert converted["choices"][0]["finish_reason"] == "tool_calls"
    message = converted["choices"][0]["message"]
    assert message["content"] == "Running locally."
    assert json.loads(message["tool_calls"][0]["function"]["arguments"]) == {"token": "<APG:v1:secret:...>"}
    assert converted["usage"] == {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}


def test_anthropic_stream_converts_text_and_incremental_tool_json_to_openai_sse() -> None:
    events = [
        {"type": "message_start", "message": {"id": "msg_1", "model": "claude-test", "usage": {"input_tokens": 8}}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Working."}},
        {
            "type": "content_block_start",
            "index": 1,
            "content_block": {"type": "tool_use", "id": "toolu_1", "name": "validate", "input": {}},
        },
        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": '{"token":"'}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": '<APG:v1:secret:...>"}'}},
        {"type": "content_block_stop", "index": 1},
        {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 9}},
        {"type": "message_stop"},
    ]
    raw = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events).encode()

    async def chunks():
        for index in range(0, len(raw), 7):
            yield raw[index : index + 7]

    async def collect() -> bytes:
        return b"".join([chunk async for chunk in anthropic_stream_to_openai(chunks())])

    output = asyncio.run(collect()).decode()
    payloads = [
        json.loads(line.removeprefix("data: "))
        for line in output.splitlines()
        if line.startswith("data: {")
    ]
    assert any(choice["delta"].get("content") == "Working." for item in payloads for choice in item.get("choices", []))
    argument_fragments = [
        call["function"]["arguments"]
        for item in payloads
        for choice in item.get("choices", [])
        for call in choice["delta"].get("tool_calls", [])
        if "arguments" in call.get("function", {})
    ]
    assert "".join(argument_fragments) == '{"token":"<APG:v1:secret:...>"}'
    assert payloads[-1]["choices"][0]["finish_reason"] == "tool_calls"
    assert output.endswith("data: [DONE]\n\n")


def test_upstream_client_uses_anthropic_endpoint_headers_and_conversion() -> None:
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
            "/v1/chat/completions",
            {"model": "claude-test", "messages": [{"role": "user", "content": "hello"}]},
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
    assert body["choices"][0]["message"]["content"] == "ok"


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


def test_openai_chat_completions_format_rejects_responses_endpoint(tmp_path) -> None:
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
        response = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "gpt-test", "input": "hello"},
        )

    assert response.status_code == 501
    assert response.json()["error"]["code"] == "APG_UPSTREAM_PROTOCOL_UNSUPPORTED"
    assert upstream.calls == []


class _ChunkStream(httpx.AsyncByteStream):
    def __init__(self, content: bytes, size: int = 9) -> None:
        self.content = content
        self.size = size

    async def __aiter__(self):
        for index in range(0, len(self.content), self.size):
            yield self.content[index : index + self.size]


def test_openai_and_anthropic_agents_materialize_tools_through_anthropic_upstream(tmp_path) -> None:
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

        openai_response = client.post(
            "/v1/chat/completions",
            headers=headers,
            json={
                "model": "claude-test",
                "messages": [{"role": "user", "content": f"Validate {raw_secret}"}],
            },
        )
        assert openai_response.status_code == 200
        openai_arguments = openai_response.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        assert json.loads(openai_arguments)["token"] == raw_secret

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

        openai_stream = client.post(
            "/v1/chat/completions",
            headers=headers,
            json={
                "model": "claude-test",
                "stream": True,
                "messages": [{"role": "user", "content": f"Validate {raw_secret}"}],
            },
        )
        assert openai_stream.status_code == 200
        assert raw_secret in openai_stream.text
        assert "<APG:v1:secret:" not in openai_stream.text
        assert "data: [DONE]" in openai_stream.text

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

    assert len(upstream_payloads) == 4
    assert all(raw_secret not in json.dumps(payload) for payload in upstream_payloads)
    assert all("<APG:v1:secret:" in json.dumps(payload) for payload in upstream_payloads)
    native_payload = upstream_payloads[1]
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
