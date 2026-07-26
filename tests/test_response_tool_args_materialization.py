from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.detector_manager import DetectorManager
from gateway.placeholder_parser import PLACEHOLDER_RE
from gateway.redaction_engine import RedactionEngine, ToolArgumentsJSONError
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
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz0" in content, "valid placeholder must be restored for the local user"
    assert "<APG:v1:" not in content, "visible content must not expose APG handles"
    assert "APG-managed protected value" not in content


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


def test_forged_placeholder_in_user_visible_text_is_never_materialized(tmp_path) -> None:
    forged = "<APG:v1:secret:secr_bogus:sess_bogus:1:AAAAAAAAAAAAAAAAAAAA>"
    fake = FakeUpstream(
        response_body={
            "choices": [{"message": {"content": f"Not valid: {forged}"}}],
        }
    )
    client = TestClient(create_app(_cfg(tmp_path), fake))

    response = _request_round_trip(client)

    assert response.status_code == 200
    content = response.json()["choices"][0]["message"]["content"]
    assert forged not in content
    assert "sk-proj-" not in content
    assert "APG-managed protected value" in content


def test_cross_session_placeholder_in_user_visible_text_fails_closed(redactor) -> None:
    placeholder, _ = redactor.sanitize_text(
        "sk-proj-abcdefghijklmnopqrstuvwxyz0",
        "session-a",
    )

    content, events = redactor.scan_local_text(placeholder, "session-b")

    assert "sk-proj-" not in content
    assert placeholder not in content
    assert content == "APG-managed protected value"
    assert any(event.get("result_code") == "APG_PLACEHOLDER_SCOPE_MISMATCH" for event in events)


def test_materialization_events_cover_cross_session_and_expired_handles(redactor, components) -> None:
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0"
    placeholder, _ = redactor.sanitize_text(secret, "sess_a")
    value, events = redactor.materialize_local_text_with_events(placeholder, "sess_b")
    assert value == placeholder
    assert events[-1]["action"] == "preserve"
    assert events[-1]["result_code"] == "APG_PLACEHOLDER_SCOPE_MISMATCH"
    assert "handle" not in events[-1]
    assert events[-1]["_audit_operation"]["direction"] == "materialization_failed"
    assert events[-1]["_audit_operation"]["placeholder_session_id"] == "sess_a"

    store, signer, policy = components
    rec = store.upsert_mapping(
        session_id="sess_expired",
        workspace_id="ws",
        scope="request",
        kind="secret",
        subtype="api_key",
        value=secret,
        store_value=True,
        materialization_class="secret",
        ttl_seconds=-1,
    )
    expired = signer.issue("secret", rec.handle_id, "sess_expired")
    expired_redactor = RedactionEngine(DetectorManager(), store, signer, policy, "ws")
    value, events = expired_redactor.materialize_local_text_with_events(expired, "sess_expired")
    assert value == expired
    assert events[-1]["result_code"] == "APG_PLACEHOLDER_EXPIRED"
    assert events[-1]["_audit_operation"]["direction"] == "materialization_failed"


def test_tool_arguments_are_materialized_as_json_and_control_characters_are_reescaped(redactor) -> None:
    session_id = "sess_control_chars"
    raw = 'line one\t"quoted"\\tail\nline two'
    record = redactor.mapping_store.upsert_mapping(
        session_id=session_id,
        workspace_id="ws",
        scope="request",
        kind="secret",
        subtype="test_control_chars",
        value=raw,
        store_value=True,
        materialization_class="secret",
        ttl_seconds=1800,
    )
    placeholder = redactor.signer.issue("secret", record.handle_id, session_id)

    encoded, events = redactor.materialize_local_tool_arguments_json_with_events(
        json.dumps({"command": "prefix " + placeholder}),
        session_id,
    )

    assert json.loads(encoded) == {"command": "prefix " + raw}
    assert "\\t" in encoded
    assert "\\n" in encoded
    assert "\\\"quoted\\\"" in encoded
    assert events[-1]["action"] == "materialize"


def test_invalid_tool_arguments_never_fall_back_to_raw_string_replacement(redactor) -> None:
    session_id = "sess_invalid_json"
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0"
    placeholder, _ = redactor.sanitize_text(secret, session_id)

    with pytest.raises(ToolArgumentsJSONError) as caught:
        redactor.materialize_local_tool_arguments_json_with_events(
            '{"api_key":"' + placeholder,
            session_id,
        )

    assert caught.value.reason_code == "invalid_tool_arguments_json"

    with pytest.raises(ToolArgumentsJSONError) as wrong_type:
        redactor.materialize_local_tool_arguments_json_with_events("[]", session_id)
    assert wrong_type.value.reason_code == "invalid_tool_arguments_type"


@pytest.mark.parametrize("endpoint", ["/v1/chat/completions", "/v1/messages"])
@pytest.mark.parametrize(
    ("arguments", "reason_code"),
    [('{"value":', "invalid_tool_arguments_json"), (42, "invalid_tool_arguments_type")],
)
def test_non_streaming_malformed_tool_arguments_return_safe_protocol_error(
    tmp_path,
    endpoint: str,
    arguments,
    reason_code: str,
) -> None:
    fake = FakeUpstream(
        response_body={
            "choices": [
                {
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_bad",
                                "type": "function",
                                "function": {"name": "broken", "arguments": arguments},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
    )
    client = TestClient(create_app(_cfg(tmp_path), fake))
    headers = {"x-api-key": "local"} if endpoint == "/v1/messages" else {"Authorization": "Bearer local"}
    request_body = {
        "model": "claude-sonnet" if endpoint == "/v1/messages" else "x",
        "messages": [{"role": "user", "content": "run the tool"}],
    }
    if endpoint == "/v1/messages":
        request_body["max_tokens"] = 64

    response = client.post(endpoint, headers=headers, json=request_body)

    assert response.status_code == 502
    assert "APG_TOOL_ARGUMENTS_INVALID" in response.text or "not valid JSON" in response.text
    audit = (tmp_path / "audit.jsonl").read_text()
    assert '"phase": "response_tool_argument_error"' in audit
    assert f'"reason_code": "{reason_code}"' in audit
    assert '{"value":' not in audit


def _extract_first_placeholder(text: str) -> str | None:
    m = PLACEHOLDER_RE.search(text)
    return m.group(0) if m else None
