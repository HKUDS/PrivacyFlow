from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.detector_manager import DetectorManager
from gateway.mapping_store import MappingStore
from gateway.placeholder_parser import PLACEHOLDER_RE, PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import (
    BalancedStreamScanner,
    PROTECTED_VALUE,
    SSEDecoder,
    STREAM_TEXT_MAX_STRICT_BLOCK,
    RedactionEngine,
)
from gateway.server import create_app
from gateway.upstream_protocol import ANTHROPIC_MESSAGES, OPENAI_CHAT_COMPLETIONS


class FakeUpstream:
    def __init__(self) -> None:
        self.calls = []

    async def request_json(self, method, path, payload=None):
        raise NotImplementedError

    async def stream_request(self, method, path, payload=None):
        self.calls.append((method, path, payload))

        async def chunks():
            yield b'data: {"choices":[{"delta":{"content":"here is the key sk-proj-abcdefghijklmnopqrstuvwxyz0"}}]}\n\n'
            yield b"data: [DONE]\n\n"

        return 200, {"content-type": "text/event-stream"}, chunks()


class ToolArgEchoUpstream:
    def __init__(self) -> None:
        self.calls = []

    async def request_json(self, method, path, payload=None):
        raise NotImplementedError

    async def stream_request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        text = json.dumps(payload)
        match = PLACEHOLDER_RE.search(text)
        placeholder = match.group(0) if match else "<APG:v1:secret:missing:sess_missing:1:missing>"

        async def chunks():
            yield (
                'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_01","function":{"name":"use_key","arguments":'
                + json.dumps(json.dumps({"api_key": placeholder}))
                + '}}]}}]}\n\n'
            ).encode()
            yield b"data: [DONE]\n\n"

        return 200, {"content-type": "text/event-stream"}, chunks()


class StaticStreamUpstream:
    def __init__(self, chunks_factory) -> None:
        self.chunks_factory = chunks_factory
        self.calls = []

    async def request_json(self, method, path, payload=None):
        raise NotImplementedError

    async def stream_request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return 200, {"content-type": "text/event-stream"}, self.chunks_factory(payload)


def _cfg(tmp_path, protocol: str = OPENAI_CHAT_COMPLETIONS):
    return GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(base_url="https://upstream", api_key="up", protocol=protocol),
    )


def _stream_request(client: TestClient, path: str, body: dict, headers: dict[str, str]) -> str:
    with client.stream("POST", path, headers=headers, json=body) as resp:
        assert resp.status_code == 200
        return resp.read().decode("utf-8")


def test_balanced_scanner_handles_every_placeholder_and_secret_split(redactor) -> None:
    session_id = "sess_stream"
    local_value = "howard@example.com"
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0"
    placeholder, _ = redactor.sanitize_text(local_value, session_id)
    assert placeholder.startswith("<APG:v1:")

    for value in (placeholder, secret):
        for split in range(1, len(value)):
            scanner = BalancedStreamScanner(redactor, session_id)
            first, _ = scanner.feed("use " + value[:split])
            second, _ = scanner.feed(value[split:] + " now")
            tail, _ = scanner.flush()
            output = first + second + tail
            assert "<APG" not in output
            if value == placeholder:
                assert local_value in output
                assert PROTECTED_VALUE not in output
            else:
                assert secret not in output
                assert PROTECTED_VALUE in output


def test_balanced_scanner_does_not_hide_an_unclassified_value_only_because_it_was_seen(redactor) -> None:
    session_id = "sess_seen_value"
    value = "violet cabin ordinary phrase"
    redactor.mapping_store.upsert_mapping(
        session_id=session_id,
        workspace_id="ws",
        scope="request",
        kind="secret",
        subtype="opaque",
        value=value,
        store_value=True,
        materialization_class="secret",
        ttl_seconds=1800,
    )

    scanner = BalancedStreamScanner(redactor, session_id)
    output, events = scanner.feed(f"Model output: {value}")
    tail, tail_events = scanner.flush()

    assert output + tail == f"Model output: {value}"
    assert events + tail_events == []


def test_balanced_scanner_folds_incomplete_and_oversized_candidates(redactor) -> None:
    scanner = BalancedStreamScanner(redactor, "sess_stream")
    output, events = scanner.feed("<APG:v1:secret:" + "x" * 5000)
    tail, tail_events = scanner.flush()
    assert output + tail == PROTECTED_VALUE
    assert any(event["subtype"] == "stream_pending_limit" for event in [*events, *tail_events])

    scanner = BalancedStreamScanner(redactor, "sess_stream")
    scanner.feed("-----BEGIN PRIVATE KEY-----\nnot-finished")
    output, events = scanner.flush()
    assert output == PROTECTED_VALUE
    assert events[-1]["subtype"] == "incomplete_stream_candidate"


def test_custom_detector_uses_strict_buffer_and_caps_text_block(tmp_path) -> None:
    manager = DetectorManager(
        detectors_config={
            "overrides": {
                "rules": {
                    "add": [
                        {
                            "id": "custom.secret",
                            "pattern": "CUSTOM_[A-Z]+",
                            "type": "MACHINE_SECRET",
                            "subtype": "custom",
                            "risk": "high",
                            "suggested_action": "redact",
                        }
                    ]
                }
            }
        }
    )
    store = MappingStore(str(tmp_path / "strict.sqlite3"))
    redactor = RedactionEngine(manager, store, PlaceholderSigner("secret", "ws"), PolicyEngine(), "ws")
    scanner = BalancedStreamScanner(redactor, "sess")
    assert scanner.strict is True
    output, events = scanner.feed("a" * (STREAM_TEXT_MAX_STRICT_BLOCK + 1))
    assert output == PROTECTED_VALUE
    assert events[-1]["subtype"] == "stream_strict_limit"
    assert scanner.flush() == ("", [])


def test_balanced_scanner_does_not_split_path_alias(redactor) -> None:
    session_id = "sess_path"
    raw_path = "/Users/howard/private/project"
    sanitized, _ = redactor.sanitize_text("repo " + raw_path, session_id)
    alias = sanitized.removeprefix("repo ")
    scanner = BalancedStreamScanner(redactor, session_id)
    first, _ = scanner.feed("x" * 300 + alias + "y" * 240)
    tail, _ = scanner.flush()
    output = first + tail
    assert alias not in output
    assert raw_path in output


def test_sse_decoder_handles_utf8_and_crlf_at_every_byte_boundary() -> None:
    wire = 'data: {"text":"你好"}\r\n\r\n'.encode("utf-8")
    decoder = SSEDecoder()
    events: list[str] = []
    for byte in wire:
        events.extend(decoder.feed(bytes([byte])))
    events.extend(decoder.finish())
    assert events == ['data: {"text":"你好"}']


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
    upstream_payload = fake.calls[0][2]
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz0" not in json.dumps(upstream_payload)
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz" not in body, "raw secret must not survive stream scan"
    assert "APG-managed protected value" in body


def test_openai_streaming_tool_call_arguments_materialize_locally(tmp_path) -> None:
    fake = ToolArgEchoUpstream()
    client = TestClient(create_app(_cfg(tmp_path), fake))
    with client.stream(
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": "Bearer local"},
        json={"model": "x", "stream": True, "messages": [{"role": "user", "content": "use sk-proj-abcdefghijklmnopqrstuvwxyz0"}]},
    ) as resp:
        body = resp.read().decode("utf-8")
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz0" in body
    assert "<APG:v1:" not in body
    assert "APG-managed protected value" not in body
    audit = (tmp_path / "audit.jsonl").read_text()
    assert '"materialized": 1' in audit
    request_summary = client.get(
        "/api/admin/audit/requests",
        headers={"Authorization": "Bearer local"},
    ).json()["requests"][0]
    detail = client.get(
        f"/api/admin/audit/requests/{request_summary['request_id']}",
        headers={"Authorization": "Bearer local"},
    ).json()
    assert request_summary["replacement_count"] == 1
    assert request_summary["materialization_count"] == 1
    assert detail["replacements"][0]["representation"] == detail["materializations"][0]["representation"]
    assert detail["materializations"][0]["tool_name"] == "use_key"
    assert detail["materializations"][0]["original"] == "***"


@pytest.mark.parametrize("emit_raw", [False, True])
def test_openai_streaming_text_protects_values_split_across_all_deltas(tmp_path, emit_raw: bool) -> None:
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0"

    def factory(payload):
        placeholder = PLACEHOLDER_RE.search(json.dumps(payload)).group(0)
        value = secret if emit_raw else placeholder

        async def chunks():
            for char in value:
                event = {"choices": [{"index": 0, "delta": {"content": char}, "finish_reason": None}]}
                yield ("data: " + json.dumps(event) + "\r\n\r\n").encode("utf-8")
            yield b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\r\n\r\n'
            yield b"data: [DONE]\r\n\r\n"

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path), StaticStreamUpstream(factory)))
    body = _stream_request(
        client,
        "/v1/chat/completions",
        {"model": "x", "stream": True, "messages": [{"role": "user", "content": "use " + secret}]},
        {"Authorization": "Bearer local"},
    )
    assert "<APG" not in body
    if emit_raw:
        assert secret not in body
        assert PROTECTED_VALUE in body
    else:
        assert secret in body
        assert PROTECTED_VALUE not in body


def test_openai_streaming_buffers_interleaved_tool_calls(tmp_path) -> None:
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0"

    def factory(payload):
        placeholder = PLACEHOLDER_RE.search(json.dumps(payload)).group(0)
        args = [json.dumps({"api_key": placeholder}), json.dumps({"token": placeholder})]

        async def chunks():
            for call_index in (0, 1):
                first = {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": call_index,
                                        "id": f"call_{call_index}",
                                        "type": "function",
                                        "function": {"name": "use_"},
                                    }
                                ]
                            },
                            "finish_reason": None,
                        }
                    ]
                }
                yield ("data: " + json.dumps(first) + "\n\n").encode()
            for offset in range(max(map(len, args))):
                for call_index, argument in enumerate(args):
                    if offset >= len(argument):
                        continue
                    event = {
                        "choices": [
                            {
                                "index": 0,
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": call_index,
                                            "function": {
                                                "name": "key" if offset == 0 else "",
                                                "arguments": argument[offset],
                                            },
                                        }
                                    ]
                                },
                                "finish_reason": None,
                            }
                        ]
                    }
                    yield ("data: " + json.dumps(event) + "\n\n").encode()
            yield b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n'
            yield b"data: [DONE]\n\n"

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path), StaticStreamUpstream(factory)))
    body = _stream_request(
        client,
        "/v1/chat/completions",
        {"model": "x", "stream": True, "messages": [{"role": "user", "content": "use " + secret}]},
        {"Authorization": "Bearer local"},
    )
    assert body.count(secret) == 2
    assert "<APG:v1:" not in body
    assert body.index(secret) < body.index('"finish_reason": "tool_calls"')


def test_invalid_streaming_tool_placeholder_is_preserved_and_audited(tmp_path) -> None:
    forged = "<APG:v1:secret:secr_fake:sess_fake:1:AAAAAAAAAAAAAAAA>"

    def factory(_payload):
        async def chunks():
            args = json.dumps({"api_key": forged})
            event = {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "id": "call_0", "function": {"name": "use_key", "arguments": args}}
                            ]
                        },
                        "finish_reason": "tool_calls",
                    }
                ]
            }
            yield ("data: " + json.dumps(event) + "\n\n").encode()
            yield b"data: [DONE]\n\n"

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path), StaticStreamUpstream(factory)))
    body = _stream_request(
        client,
        "/v1/chat/completions",
        {"model": "x", "stream": True, "messages": [{"role": "user", "content": "hello"}]},
        {"Authorization": "Bearer local"},
    )
    assert forged in body
    audit = (tmp_path / "audit.jsonl").read_text()
    assert "APG_PLACEHOLDER_INVALID_MAC" in audit
    assert forged not in audit


@pytest.mark.parametrize("endpoint", ["/v1/chat/completions", "/v1/messages"])
def test_malformed_streaming_tool_arguments_return_safe_error_and_specific_audit(tmp_path, endpoint: str) -> None:
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0"

    def factory(payload):
        placeholder = PLACEHOLDER_RE.search(json.dumps(payload)).group(0)

        async def chunks():
            if endpoint == "/v1/messages":
                events = [
                    {
                        "type": "content_block_start",
                        "index": 0,
                        "content_block": {
                            "type": "tool_use",
                            "id": "toolu_bad",
                            "name": "use_key",
                            "input": {},
                        },
                    },
                    {
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": '{"api_key":"' + placeholder,
                        },
                    },
                    {"type": "content_block_stop", "index": 0},
                ]
                for event in events:
                    yield (
                        f"event: {event['type']}\n"
                        f"data: {json.dumps(event)}\n\n"
                    ).encode()
            else:
                event = {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": "call_bad",
                                        "type": "function",
                                        "function": {
                                            "name": "use_key",
                                            "arguments": '{"api_key":"' + placeholder,
                                        },
                                    }
                                ]
                            },
                            "finish_reason": "tool_calls",
                        }
                    ]
                }
                yield ("data: " + json.dumps(event) + "\n\n").encode()
                yield b"data: [DONE]\n\n"

        return chunks()

    protocol = ANTHROPIC_MESSAGES if endpoint == "/v1/messages" else OPENAI_CHAT_COMPLETIONS
    client = TestClient(create_app(_cfg(tmp_path, protocol), StaticStreamUpstream(factory)))
    headers = {"x-api-key": "local"} if endpoint == "/v1/messages" else {"Authorization": "Bearer local"}
    request_body = {
        "model": "claude-sonnet" if endpoint == "/v1/messages" else "x",
        "stream": True,
        "messages": [{"role": "user", "content": "use " + secret}],
    }
    if endpoint == "/v1/messages":
        request_body["max_tokens"] = 64

    body = _stream_request(client, endpoint, request_body, headers)

    assert secret not in body
    assert "<APG:v1:" not in body
    assert "not valid JSON" in body
    if endpoint == "/v1/chat/completions":
        assert "APG_TOOL_ARGUMENTS_INVALID" in body
    else:
        assert "event: error" in body
    audit = (tmp_path / "audit.jsonl").read_text()
    assert '"parse_errors": 1' in audit
    assert '"stream_parse_errors": 0' in audit
    assert '"tool_argument_json_errors": {"invalid_tool_arguments_json": 1}' in audit
    assert '"termination": "protocol_error"' in audit


def test_malformed_openai_stream_fails_closed(tmp_path) -> None:
    raw = "sk-proj-abcdefghijklmnopqrstuvwxyz0"

    def factory(_payload):
        async def chunks():
            yield f"data: not-json {raw}\n\n".encode()

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path), StaticStreamUpstream(factory)))
    body = _stream_request(
        client,
        "/v1/chat/completions",
        {"model": "x", "stream": True, "messages": [{"role": "user", "content": "hello"}]},
        {"Authorization": "Bearer local"},
    )
    assert raw not in body
    assert "APG_STREAM_PARSE_ERROR" in body
    audit = (tmp_path / "audit.jsonl").read_text()
    assert '"parse_errors": 1' in audit
    assert '"stream_parse_errors": 1' in audit
    assert '"tool_argument_json_errors": {}' in audit
    assert '"termination": "protocol_error"' in audit


def test_anthropic_streaming_text_and_tool_args_materialize_locally(tmp_path) -> None:
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0"

    def factory(payload):
        placeholder = PLACEHOLDER_RE.search(json.dumps(payload)).group(0)
        arguments = json.dumps({"api_key": placeholder})

        async def chunks():
            initial_events = [
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_1",
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-sonnet",
                        "content": [],
                        "stop_reason": None,
                        "usage": {"input_tokens": 4, "output_tokens": 0},
                    },
                },
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            ]
            for event in initial_events:
                yield (
                    f"event: {event['type']}\n"
                    f"data: {json.dumps(event)}\n\n"
                ).encode()
            for char in placeholder:
                event = {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": char},
                }
                yield (
                    f"event: {event['type']}\n"
                    f"data: {json.dumps(event)}\n\n"
                ).encode()
            middle_events = [
                {"type": "content_block_stop", "index": 0},
                {
                    "type": "content_block_start",
                    "index": 1,
                    "content_block": {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "use_key",
                        "input": {},
                    },
                },
            ]
            for event in middle_events:
                yield (
                    f"event: {event['type']}\n"
                    f"data: {json.dumps(event)}\n\n"
                ).encode()
            for char in arguments:
                event = {
                    "type": "content_block_delta",
                    "index": 1,
                    "delta": {"type": "input_json_delta", "partial_json": char},
                }
                yield (
                    f"event: {event['type']}\n"
                    f"data: {json.dumps(event)}\n\n"
                ).encode()
            final_events = [
                {"type": "content_block_stop", "index": 1},
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                    "usage": {"output_tokens": 4},
                },
                {"type": "message_stop"},
            ]
            for event in final_events:
                yield (
                    f"event: {event['type']}\n"
                    f"data: {json.dumps(event)}\n\n"
                ).encode()

        return chunks()

    client = TestClient(
        create_app(
            _cfg(tmp_path, ANTHROPIC_MESSAGES),
            StaticStreamUpstream(factory),
        )
    )
    body = _stream_request(
        client,
        "/v1/messages",
        {
            "model": "claude-sonnet",
            "stream": True,
            "max_tokens": 128,
            "messages": [{"role": "user", "content": "use " + secret}],
            "tools": [{"name": "use_key", "input_schema": {"type": "object"}}],
        },
        {"x-api-key": "local"},
    )
    assert body.count(secret) >= 2
    assert secret in body
    assert "<APG:v1:" not in body
    assert '"name": "use_key"' in body
    request_summary = client.get(
        "/api/admin/audit/requests",
        headers={"Authorization": "Bearer local"},
    ).json()["requests"][0]
    detail = client.get(
        f"/api/admin/audit/requests/{request_summary['request_id']}",
        headers={"Authorization": "Bearer local"},
    ).json()
    assert request_summary["replacement_count"] == 1
    assert request_summary["materialization_count"] == 2
    assert all(
        detail["replacements"][0]["protected_value_id"] == event["protected_value_id"]
        for event in detail["materializations"]
    )
    assert {event["sink"] for event in detail["materializations"]} == {"local_user", "local_tool"}
    assert next(event for event in detail["materializations"] if event["sink"] == "local_tool")["tool_name"] == "use_key"


def test_anthropic_thinking_signature_is_preserved_as_protocol_metadata(tmp_path) -> None:
    signature = "b2867577-f815-4294-8687-9855240c918c"

    def factory(_payload):
        async def chunks():
            events = [
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_1",
                        "type": "message",
                        "role": "assistant",
                        "model": "deepseek-v4-flash",
                        "content": [],
                        "stop_reason": None,
                        "usage": {"input_tokens": 4, "output_tokens": 0},
                    },
                },
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "thinking", "thinking": "", "signature": ""},
                },
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "thinking_delta", "thinking": "safe reasoning"},
                },
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "signature_delta", "signature": signature},
                },
                {"type": "content_block_stop", "index": 0},
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 4},
                },
                {"type": "message_stop"},
            ]
            for event in events:
                yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path, ANTHROPIC_MESSAGES), StaticStreamUpstream(factory)))
    body = _stream_request(
        client,
        "/v1/messages",
        {"model": "deepseek-v4-flash", "stream": True, "max_tokens": 64, "messages": [{"role": "user", "content": "hello"}]},
        {"x-api-key": "local"},
    )

    assert signature in body
    assert PROTECTED_VALUE not in body


def test_malformed_anthropic_stream_returns_safe_error(tmp_path) -> None:
    raw = "sk-proj-abcdefghijklmnopqrstuvwxyz0"

    def factory(_payload):
        async def chunks():
            yield f"data: not-json {raw}\n\n".encode()

        return chunks()

    client = TestClient(
        create_app(
            _cfg(tmp_path, ANTHROPIC_MESSAGES),
            StaticStreamUpstream(factory),
        )
    )
    body = _stream_request(
        client,
        "/v1/messages",
        {"model": "claude-sonnet", "stream": True, "max_tokens": 64, "messages": [{"role": "user", "content": "hello"}]},
        {"x-api-key": "local"},
    )
    assert raw not in body
    assert "event: error" in body
    assert "could not be safely parsed" in body
