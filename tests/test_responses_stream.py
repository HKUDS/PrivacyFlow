from __future__ import annotations

import json

from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.placeholder_parser import PLACEHOLDER_RE
from gateway.redaction_engine import PROTECTED_VALUE, SSEDecoder, parse_sse_event
from gateway.server import APG_UPSTREAM_SYSTEM_PROMPT, create_app


SECRET = "sk-proj-abcdefghijklmnopqrstuvwxyz0"


def _placeholder_of_kind(text: str, kind: str) -> str:
    return next(match.group(0) for match in PLACEHOLDER_RE.finditer(text) if match.group("kind") == kind)


class ResponsesStreamUpstream:
    def __init__(self, factory) -> None:
        self.factory = factory
        self.calls = []

    async def request_json(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return 200, {"content-type": "application/json"}, {"id": "resp_1", "output": []}

    async def stream_request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return 200, {"content-type": "text/event-stream"}, self.factory(payload)


class MutableResponsesUpstream:
    def __init__(self) -> None:
        self.calls = []
        self.response_body = {"id": "resp_1", "output": []}

    async def request_json(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return 200, {"content-type": "application/json"}, self.response_body


def _cfg(tmp_path) -> GatewayConfig:
    return GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="responses-secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(base_url="https://upstream", api_key="up"),
    )


def _event(event_type: str, payload: dict) -> bytes:
    return f"event: {event_type}\ndata: {json.dumps({'type': event_type, **payload})}\n\n".encode()


def _stream(client: TestClient, body: dict) -> str:
    with client.stream("POST", "/v1/responses", headers={"Authorization": "Bearer local"}, json=body) as response:
        assert response.status_code == 200
        return response.read().decode()


def test_responses_stream_injects_instructions_and_folds_split_secret(tmp_path) -> None:
    def factory(payload):
        placeholder = _placeholder_of_kind(json.dumps(payload), "secret")

        async def chunks():
            yield _event("response.created", {"response": {"id": "resp_1", "status": "in_progress", "output": []}})
            for char in placeholder:
                yield _event(
                    "response.output_text.delta",
                    {"item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": char},
                )
            yield _event(
                "response.output_text.done",
                {"item_id": "msg_1", "output_index": 0, "content_index": 0, "text": placeholder},
            )
            yield _event(
                "response.completed",
                {
                    "response": {
                        "id": "resp_1",
                        "status": "completed",
                        "output": [
                            {
                                "id": "msg_1",
                                "type": "message",
                                "content": [{"type": "output_text", "text": placeholder}],
                            }
                        ],
                    }
                },
            )

        return chunks()

    upstream = ResponsesStreamUpstream(factory)
    client = TestClient(create_app(_cfg(tmp_path), upstream))
    body = _stream(client, {"model": "x", "stream": True, "instructions": "Be concise.", "input": "use " + SECRET})
    sent = upstream.calls[0][2]
    assert APG_UPSTREAM_SYSTEM_PROMPT in sent["instructions"]
    assert sent["instructions"].endswith("Be concise.")
    assert SECRET not in json.dumps(sent)
    assert SECRET not in body
    assert "<APG:v1:" not in body
    assert PROTECTED_VALUE in body
    assert 'event: response.output_text.delta' in body
    assert 'event: response.completed' in body


def test_responses_stream_buffers_and_materializes_interleaved_function_arguments(tmp_path) -> None:
    def factory(payload):
        placeholder = _placeholder_of_kind(json.dumps(payload), "secret")
        arguments = [json.dumps({"api_key": placeholder}), json.dumps({"token": placeholder})]

        async def chunks():
            for offset in range(max(map(len, arguments))):
                for index, argument in enumerate(arguments):
                    if offset < len(argument):
                        yield _event(
                            "response.function_call_arguments.delta",
                            {"item_id": f"call_{index}", "output_index": index, "delta": argument[offset]},
                        )
            for index, argument in enumerate(arguments):
                yield _event(
                    "response.function_call_arguments.done",
                    {"item_id": f"call_{index}", "output_index": index, "arguments": argument},
                )
            yield _event("response.completed", {"response": {"id": "resp_1", "status": "completed", "output": []}})

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(factory)))
    body = _stream(client, {"model": "x", "stream": True, "input": "use " + SECRET})
    assert body.count(SECRET) == 4
    assert "<APG:v1:" not in body
    assert body.index(SECRET) < body.index("response.function_call_arguments.done")
    audit = (tmp_path / "audit.jsonl").read_text()
    assert '"materialized": 2' in audit


def test_responses_stream_scans_reasoning_refusal_and_unknown_delta_fails_closed(tmp_path) -> None:
    async def chunks():
        yield _event(
            "response.reasoning_summary_text.delta",
            {"item_id": "r1", "output_index": 0, "content_index": 0, "delta": SECRET},
        )
        yield _event(
            "response.reasoning_summary_text.done",
            {"item_id": "r1", "output_index": 0, "content_index": 0, "text": SECRET},
        )
        yield _event("response.unknown.delta", {"delta": "unsafe"})

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(lambda _: chunks())))
    body = _stream(client, {"model": "x", "stream": True, "input": "hello"})
    assert SECRET not in body
    assert PROTECTED_VALUE in body
    assert "APG_STREAM_PARSE_ERROR" in body
    assert "event: error" in body


def test_responses_sse_parser_preserves_event_name_and_multiline_data() -> None:
    wire = b"event: response.output_text.delta\r\ndata: {\"type\":\r\ndata: \"response.output_text.delta\"}\r\n\r\n"
    decoder = SSEDecoder()
    raw_events = []
    for byte in wire:
        raw_events.extend(decoder.feed(bytes([byte])))
    raw_events.extend(decoder.finish())
    parsed = parse_sse_event(raw_events[0])
    assert parsed is not None
    assert parsed.event == "response.output_text.delta"
    assert parsed.data == '{"type":\n"response.output_text.delta"}'


def test_non_streaming_responses_materializes_function_call_and_restores_pii(tmp_path) -> None:
    upstream = MutableResponsesUpstream()
    client = TestClient(create_app(_cfg(tmp_path), upstream))
    first = client.post(
        "/v1/responses",
        headers={"Authorization": "Bearer local"},
        json={"model": "x", "input": f"use {SECRET} and contact alice@example.com"},
    )
    assert first.status_code == 200
    sent = json.dumps(upstream.calls[0][2])
    secret_placeholder = _placeholder_of_kind(sent, "secret")
    pii_placeholder = _placeholder_of_kind(sent, "pii")
    upstream.response_body = {
        "id": "resp_abcdefghijklmnopqrstuvwxyz1234567890",
        "object": "response",
        "status": "completed",
        "output": [
            {"id": "call_1", "type": "function_call", "name": "use_key", "arguments": json.dumps({"api_key": secret_placeholder})},
            {"id": "msg_1", "type": "message", "content": [{"type": "output_text", "text": f"Email {pii_placeholder}; key {secret_placeholder}"}]},
        ],
    }
    second = client.post(
        "/v1/responses",
        headers={"Authorization": "Bearer local"},
        json={"model": "x", "input": "continue"},
    )
    body = second.json()
    assert body["id"] == "resp_abcdefghijklmnopqrstuvwxyz1234567890"
    arguments = json.loads(body["output"][0]["arguments"])
    assert arguments["api_key"] == SECRET
    visible = body["output"][1]["content"][0]["text"]
    assert visible == f"Email alice@example.com; key {PROTECTED_VALUE}"


def test_responses_stream_flushes_tool_arguments_at_eof_and_rejects_malformed_json(tmp_path) -> None:
    def eof_factory(payload):
        placeholder = _placeholder_of_kind(json.dumps(payload), "secret")

        async def chunks():
            yield _event(
                "response.function_call_arguments.delta",
                {"item_id": "call_1", "output_index": 0, "delta": json.dumps({"api_key": placeholder})},
            )

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(eof_factory)))
    body = _stream(client, {"model": "x", "stream": True, "input": "use " + SECRET})
    assert SECRET in body
    assert "<APG:v1:" not in body

    async def malformed():
        yield b"event: response.output_text.delta\ndata: not-json\n\n"

    bad_client = TestClient(create_app(_cfg(tmp_path / "bad"), ResponsesStreamUpstream(lambda _: malformed())))
    bad_body = _stream(bad_client, {"model": "x", "stream": True, "input": "hello"})
    assert "APG_STREAM_PARSE_ERROR" in bad_body
    assert "event: error" in bad_body


def test_responses_stream_raw_pii_split_across_deltas_has_no_visible_handle(tmp_path) -> None:
    email = "alice@example.com"

    async def chunks():
        for char in email:
            yield _event(
                "response.output_text.delta",
                {"item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": char},
            )
        yield _event(
            "response.output_text.done",
            {"item_id": "msg_1", "output_index": 0, "content_index": 0, "text": email},
        )
        yield _event("response.completed", {"response": {"id": "resp_1", "status": "completed", "output": []}})

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(lambda _: chunks())))
    body = _stream(client, {"model": "x", "stream": True, "input": "hello"})
    assert email in body
    assert "<APG" not in body
