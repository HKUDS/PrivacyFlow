from __future__ import annotations

import json

from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.placeholder_parser import PLACEHOLDER_RE
from gateway.redaction_engine import PROTECTED_VALUE, SSEDecoder, parse_sse_event
from gateway.server import APG_UPSTREAM_SYSTEM_PROMPT, create_app
from gateway.upstream_protocol import OPENAI_RESPONSES


SECRET = "sk-proj-abcdefghijklmnopqrstuvwxyz0"


def _placeholder_of_kind(text: str, kind: str) -> str:
    return next(match.group(0) for match in PLACEHOLDER_RE.finditer(text) if match.group("kind") == kind)


class ResponsesStreamUpstream:
    def __init__(
        self,
        factory,
        *,
        headers: dict[str, str] | None = None,
        status: int = 200,
        content_type: str = "text/event-stream",
    ) -> None:
        self.factory = factory
        self.headers = dict(headers or {})
        self.status = status
        self.content_type = content_type
        self.calls = []

    async def request_json(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return 200, {"content-type": "application/json"}, {"id": "resp_1", "output": []}

    async def stream_request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return self.status, {"content-type": self.content_type, **self.headers}, self.factory(payload)


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
        upstream=UpstreamConfig(base_url="https://upstream", api_key="up", protocol=OPENAI_RESPONSES),
    )


def _event(event_type: str, payload: dict) -> bytes:
    return f"event: {event_type}\ndata: {json.dumps({'type': event_type, **payload})}\n\n".encode()


def _stream(client: TestClient, body: dict) -> str:
    with client.stream("POST", "/v1/responses", headers={"Authorization": "Bearer local"}, json=body) as response:
        assert response.status_code == 200
        return response.read().decode()


def test_responses_stream_injects_instructions_and_restores_split_placeholder(tmp_path) -> None:
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
    assert SECRET in body
    assert "<APG:v1:" not in body
    assert PROTECTED_VALUE not in body
    assert 'event: response.output_text.delta' in body
    assert 'event: response.completed' in body


def test_responses_stream_audits_upstream_failure_and_trace_without_sensitive_message(tmp_path) -> None:
    async def chunks():
        yield _event(
            "response.failed",
            {
                "response": {
                    "id": "resp_failed",
                    "status": "failed",
                    "error": {
                        "type": "server_error",
                        "code": "concurrency_limit_exceeded",
                        "message": f"Concurrency limit exceeded for {SECRET}",
                    },
                }
            },
        )

    upstream = ResponsesStreamUpstream(
        lambda _: chunks(),
        headers={
            "x-request-id": "up_req_123",
            "authorization": "Bearer must-not-be-recorded",
        },
    )
    client = TestClient(create_app(_cfg(tmp_path), upstream))
    with client.stream(
        "POST",
        "/v1/responses",
        headers={"Authorization": "Bearer local"},
        json={"model": "x", "stream": True, "input": "hello"},
    ) as response:
        body = response.read().decode()
        assert response.headers["x-request-id"] == "up_req_123"

    assert "response.failed" in body
    assert SECRET not in body
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    complete = next(row for row in rows if row.get("phase") == "response_stream_complete")
    assert complete["termination"] == "failed"
    assert complete["upstream_error_event"] == "response.failed"
    assert complete["upstream_error_type"] == "server_error"
    assert complete["upstream_error_code"] == "concurrency_limit_exceeded"
    assert complete["upstream_trace_headers"] == {"x-request-id": "up_req_123"}
    audit_text = (tmp_path / "audit.jsonl").read_text()
    assert SECRET not in audit_text
    assert "must-not-be-recorded" not in audit_text


def test_responses_stream_eof_without_terminal_event_is_audited_as_disconnected(tmp_path) -> None:
    async def chunks():
        yield _event("response.created", {"response": {"id": "resp_1", "status": "in_progress", "output": []}})

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(lambda _: chunks())))
    _stream(client, {"model": "x", "stream": True, "input": "hello"})
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    complete = next(row for row in rows if row.get("phase") == "response_stream_complete")
    assert complete["termination"] == "upstream_disconnected"


def test_responses_stream_top_level_error_event_is_audited_as_failed(tmp_path) -> None:
    async def chunks():
        yield _event(
            "error",
            {
                "code": "rate_limit_exceeded",
                "message": "Please retry later",
            },
        )

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(lambda _: chunks())))
    body = _stream(client, {"model": "x", "stream": True, "input": "hello"})
    assert "rate_limit_exceeded" in body
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    complete = next(row for row in rows if row.get("phase") == "response_stream_complete")
    assert complete["termination"] == "failed"
    assert complete["upstream_error_event"] == "error"
    assert complete["upstream_error_type"] == "error"
    assert complete["upstream_error_code"] == "rate_limit_exceeded"


def test_responses_stream_preserves_non_success_json_error_and_audits_code(tmp_path) -> None:
    async def chunks():
        yield json.dumps(
            {
                "error": {
                    "type": "server_error",
                    "code": "concurrency_limit_exceeded",
                    "message": "Please retry later",
                }
            }
        ).encode()

    upstream = ResponsesStreamUpstream(
        lambda _: chunks(),
        status=503,
        content_type="application/json",
        headers={"x-request-id": "up_req_503"},
    )
    client = TestClient(create_app(_cfg(tmp_path), upstream))
    with client.stream(
        "POST",
        "/v1/responses",
        headers={"Authorization": "Bearer local"},
        json={"model": "x", "stream": True, "input": "hello"},
    ) as response:
        assert response.status_code == 503
        assert response.headers["x-request-id"] == "up_req_503"
        response_body = json.loads(response.read())
        assert response_body["error"]["code"] == "concurrency_limit_exceeded"

    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    complete = next(row for row in rows if row.get("phase") == "response_stream_complete")
    assert complete["termination"] == "failed"
    assert complete["upstream_error_type"] == "server_error"
    assert complete["upstream_error_code"] == "concurrency_limit_exceeded"


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


def test_deepseek_reasoning_text_and_incomplete_are_valid_responses_events(tmp_path) -> None:
    def factory(payload):
        placeholder = _placeholder_of_kind(json.dumps(payload), "secret")

        async def chunks():
            for char in placeholder:
                yield _event(
                    "response.reasoning_text.delta",
                    {"item_id": "reasoning_1", "output_index": 0, "content_index": 0, "delta": char},
                )
            yield _event(
                "response.reasoning_text.done",
                {"item_id": "reasoning_1", "output_index": 0, "content_index": 0, "text": placeholder},
            )
            yield _event(
                "response.incomplete",
                {
                    "response": {
                        "id": "resp_deepseek",
                        "status": "incomplete",
                        "output": [
                            {
                                "id": "reasoning_1",
                                "type": "reasoning",
                                "content": [{"type": "reasoning_text", "text": placeholder}],
                            }
                        ],
                    }
                },
            )

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(factory)))
    body = _stream(client, {"model": "deepseek-v4-flash", "stream": True, "input": "use " + SECRET})

    assert "response.reasoning_text.delta" in body
    assert "response.reasoning_text.done" in body
    assert "response.incomplete" in body
    assert "APG_STREAM_PARSE_ERROR" not in body
    assert SECRET in body
    assert "<APG:v1:" not in body

    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    complete = next(row for row in rows if row.get("phase") == "response_stream_complete")
    assert complete["termination"] == "incomplete"
    assert complete["parse_errors"] == 0


def test_deepseek_custom_tool_input_is_buffered_and_materialized_locally(tmp_path) -> None:
    def factory(payload):
        placeholder = _placeholder_of_kind(json.dumps(payload), "secret")
        patch = f"*** Begin Patch\n+API_KEY={placeholder}\n*** End Patch"

        async def chunks():
            for char in patch:
                yield _event(
                    "response.custom_tool_call_input.delta",
                    {"item_id": "custom_1", "output_index": 0, "delta": char},
                )
            yield _event(
                "response.custom_tool_call_input.done",
                {"item_id": "custom_1", "output_index": 0, "input": patch},
            )
            yield _event(
                "response.completed",
                {
                    "response": {
                        "id": "resp_deepseek",
                        "status": "completed",
                        "output": [
                            {
                                "id": "custom_1",
                                "type": "custom_tool_call",
                                "name": "apply_patch",
                                "input": patch,
                            }
                        ],
                    }
                },
            )

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(factory)))
    body = _stream(client, {"model": "deepseek-v4-flash", "stream": True, "input": "use " + SECRET})

    assert "response.custom_tool_call_input.delta" in body
    assert "response.custom_tool_call_input.done" in body
    assert "response.completed" in body
    assert "APG_STREAM_PARSE_ERROR" not in body
    assert SECRET in body
    assert "<APG:v1:" not in body


def test_responses_stream_supports_code_interpreter_and_mcp_text_events(tmp_path) -> None:
    def factory(payload):
        placeholder = _placeholder_of_kind(json.dumps(payload), "secret")
        code = f"token = {placeholder!r}"
        arguments = json.dumps({"token": placeholder})

        async def chunks():
            for char in code:
                yield _event(
                    "response.code_interpreter_call_code.delta",
                    {"item_id": "code_1", "output_index": 0, "delta": char},
                )
            yield _event(
                "response.code_interpreter_call_code.done",
                {"item_id": "code_1", "output_index": 0, "code": code},
            )
            for char in arguments:
                yield _event(
                    "response.mcp_call_arguments.delta",
                    {"item_id": "mcp_1", "output_index": 1, "delta": char},
                )
            yield _event(
                "response.mcp_call_arguments.done",
                {"item_id": "mcp_1", "output_index": 1, "arguments": arguments},
            )
            yield _event("response.completed", {"response": {"id": "resp_1", "status": "completed", "output": []}})

        return chunks()

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(factory)))
    body = _stream(client, {"model": "x", "stream": True, "input": "use " + SECRET})

    assert "response.code_interpreter_call_code.delta" in body
    assert "response.code_interpreter_call_code.done" in body
    assert "response.mcp_call_arguments.delta" in body
    assert "response.mcp_call_arguments.done" in body
    assert "APG_STREAM_PARSE_ERROR" not in body
    assert SECRET in body
    assert "<APG:v1:" not in body


def test_responses_stream_passes_audio_and_image_events_through_unchanged(tmp_path) -> None:
    audio = "c2stcHJvai1hdWRpby1ieXRlcw=="
    image = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"

    async def chunks():
        yield _event("response.audio.delta", {"response_id": "resp_1", "delta": audio})
        yield _event("response.audio.transcript.delta", {"response_id": "resp_1", "delta": SECRET})
        yield _event(
            "response.image_generation_call.partial_image",
            {"item_id": "image_1", "output_index": 0, "partial_image_index": 0, "partial_image_b64": image},
        )
        yield _event(
            "response.completed",
            {
                "response": {
                    "id": "resp_1",
                    "status": "completed",
                    "output": [{"id": "image_1", "type": "image_generation_call", "result": image}],
                }
            },
        )

    client = TestClient(create_app(_cfg(tmp_path), ResponsesStreamUpstream(lambda _: chunks())))
    body = _stream(client, {"model": "x", "stream": True, "input": "hello"})

    assert audio in body
    assert image in body
    assert SECRET in body
    assert "APG_STREAM_PARSE_ERROR" not in body


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
    assert visible == f"Email alice@example.com; key {SECRET}"


def test_responses_request_passes_multimodal_payloads_and_protocol_ids_unchanged(tmp_path) -> None:
    upstream = MutableResponsesUpstream()
    client = TestClient(create_app(_cfg(tmp_path), upstream))
    image_url = f"https://example.test/private.png?token={SECRET}"
    file_id = f"file-{SECRET}"
    container_id = f"cntr-{SECRET}"

    response = client.post(
        "/v1/responses",
        headers={"Authorization": "Bearer local"},
        json={
            "model": "x",
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_image", "image_url": image_url},
                        {"type": "input_file", "file_id": file_id, "file_data": SECRET, "filename": "private.txt"},
                    ],
                },
                {"type": "code_interpreter_call", "id": "code_1", "container_id": container_id, "code": "print('ok')"},
            ],
            "tools": [{"type": "code_interpreter", "container": {"type": "auto", "file_ids": [file_id]}}],
        },
    )

    assert response.status_code == 200
    sent = upstream.calls[0][2]
    assert sent["input"][0]["content"][0]["image_url"] == image_url
    assert sent["input"][0]["content"][1]["file_id"] == file_id
    assert sent["input"][0]["content"][1]["file_data"] == SECRET
    assert sent["input"][1]["container_id"] == container_id
    assert sent["tools"][0]["container"]["file_ids"] == [file_id]


def test_responses_request_with_dict_typed_type_field_is_walked_not_crashed(tmp_path) -> None:
    upstream = MutableResponsesUpstream()
    client = TestClient(create_app(_cfg(tmp_path), upstream))
    # A container whose "type" value is itself a dict is unhashable; membership
    # checks against the opaque/protocol sets must not raise TypeError.
    response = client.post(
        "/v1/responses",
        headers={"Authorization": "Bearer local"},
        json={
            "model": "x",
            "input": [
                {"type": {"nested": "metadata"}, "id": "obj_1", "text": f"key {SECRET}"},
            ],
        },
    )

    assert response.status_code == 200
    sent = upstream.calls[0][2]
    assert sent["input"][0]["type"] == {"nested": "metadata"}
    assert sent["input"][0]["id"] == "obj_1"
    # The plaintext secret in the same container is still replaced.
    assert SECRET not in json.dumps(sent)
    assert _placeholder_of_kind(json.dumps(sent), "secret")


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
