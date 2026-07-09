from __future__ import annotations

import json


def test_api_key_redacted_before_upstream(redactor) -> None:
    body = {"messages": [{"content": "use sk-proj-abcdefghijklmnopqrstuvwxyz123456"}]}
    sanitized, events = redactor.sanitize_json(body, "sess_1")
    text = json.dumps(sanitized)
    assert "sk-proj-" not in text
    assert "<APG:v1:secret:" in text
    assert events[0]["subtype"] == "openai_api_key"


def test_email_pseudonymized_consistently(redactor) -> None:
    a, _ = redactor.sanitize_text("howard@example.com", "sess_1")
    b, _ = redactor.sanitize_text("howard@example.com", "sess_1")
    assert a == b
    assert "howard@example.com" not in a


def test_local_path_aliased(redactor) -> None:
    sanitized, _ = redactor.sanitize_text("cd /Users/howard/private/project", "sess_1")
    assert "/Users/howard" not in sanitized
    assert "/workspace/" in sanitized


def test_same_basename_paths_get_distinct_aliases(redactor) -> None:
    a, _ = redactor.sanitize_text("repo /private/tmp/a/repo", "sess_1")
    b, _ = redactor.sanitize_text("repo /private/tmp/b/repo", "sess_1")
    assert a != b
    assert "/private/tmp" not in a + b


def test_tool_call_protocol_ids_are_not_redacted(redactor) -> None:
    body = {
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_01_abcdefghijklmnopqrstuvwxyz1234567890",
                "content": "ok",
            },
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_02_abcdefghijklmnopqrstuvwxyz1234567890",
                        "type": "function",
                        "function": {"name": "read", "arguments": "{}"},
                    }
                ],
            },
        ]
    }
    sanitized, _ = redactor.sanitize_json(body, "sess_1")
    text = json.dumps(sanitized)
    assert "call_01_abcdefghijklmnopqrstuvwxyz1234567890" in text
    assert "call_02_abcdefghijklmnopqrstuvwxyz1234567890" in text


def test_local_response_materializes_path_alias(redactor) -> None:
    sanitized, _ = redactor.sanitize_text("read /Users/howard/private/project/src/app.py", "sess_1")
    assert "/workspace/" in sanitized
    restored = redactor.materialize_local_text(sanitized, "sess_1")
    assert "/Users/howard/private/project/src/app.py" in restored


def test_raw_secret_not_in_audit_log(tmp_path) -> None:
    from gateway.audit_logger import AuditLogger

    path = tmp_path / "audit.jsonl"
    AuditLogger(str(path)).log({"raw": "sk-proj-abcdefghijklmnopqrstuvwxyz123456", "msg": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"})
    data = path.read_text()
    assert "sk-proj-" not in data
    assert "Authorization: Bearer" not in data


def test_response_containing_secret_is_redacted(redactor) -> None:
    from gateway.response_scanner import ResponseScanner

    scanned, _ = ResponseScanner(redactor).scan_response_json({"choices": [{"message": {"content": "sk-proj-abcdefghijklmnopqrstuvwxyz123456"}}]}, "sess_1")
    assert "sk-proj-" not in json.dumps(scanned)


def test_tool_schema_descriptions_are_scanned(redactor) -> None:
    body = {"tools": [{"function": {"description": "token sk-proj-abcdefghijklmnopqrstuvwxyz123456"}}]}
    sanitized, _ = redactor.sanitize_json(body, "sess_1")
    assert "sk-proj-" not in json.dumps(sanitized)


def test_tool_schema_function_names_are_not_redacted(redactor) -> None:
    body = {"tools": [{"type": "function", "function": {"name": "apg_openai_connectivity_check", "description": "broker tool"}}]}
    sanitized, _ = redactor.sanitize_json(body, "sess_1")
    assert sanitized["tools"][0]["function"]["name"] == "apg_openai_connectivity_check"


def test_recursive_json_fields_are_scanned(redactor) -> None:
    body = {"metadata": {"nested": ["email howard@example.com"]}, "response_format": {"description": "sk-proj-abcdefghijklmnopqrstuvwxyz123456"}}
    sanitized, _ = redactor.sanitize_json(body, "sess_1")
    text = json.dumps(sanitized)
    assert "howard@example.com" not in text
    assert "sk-proj-" not in text
