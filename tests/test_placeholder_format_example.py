from __future__ import annotations

import pytest

from gateway.detector_manager import DetectorManager
from gateway.placeholder_parser import (
    APG_PLACEHOLDER_FORMAT_EXAMPLE,
    PLACEHOLDER_RE,
)
from gateway.redaction_engine import BalancedStreamScanner, PROTECTED_VALUE
from gateway.server import APG_UPSTREAM_SYSTEM_PROMPT


def test_prompt_uses_the_reserved_placeholder_format_example() -> None:
    assert f"`{APG_PLACEHOLDER_FORMAT_EXAMPLE}`" in APG_UPSTREAM_SYSTEM_PROMPT
    assert "never substitute one placeholder for another" in APG_UPSTREAM_SYSTEM_PROMPT
    assert (
        "repeated occurrences of the exact same APG placeholder refer to the same protected local value"
        in APG_UPSTREAM_SYSTEM_PROMPT
    )
    assert (
        "Different placeholders do not imply that their underlying values are equal or different"
        in APG_UPSTREAM_SYSTEM_PROMPT
    )
    assert "emit its exact APG placeholder unchanged" in APG_UPSTREAM_SYSTEM_PROMPT
    assert "APG will restore valid placeholders locally before showing the answer to the user" in APG_UPSTREAM_SYSTEM_PROMPT
    assert PLACEHOLDER_RE.fullmatch(APG_PLACEHOLDER_FORMAT_EXAMPLE) is None


def test_every_detector_module_silently_ignores_only_the_example() -> None:
    manager = DetectorManager(
        detectors_config={
            "overrides": {
                "rules": {
                    "add": [
                        {
                            "id": "custom.example_inner_text",
                            "pattern": "pii",
                            "type": "PII",
                            "subtype": "custom_inner_text",
                            "confidence": 1.0,
                            "risk": "high",
                            "suggested_action": "pseudonymize",
                        }
                    ]
                }
            }
        }
    )

    assert manager.scan(APG_PLACEHOLDER_FORMAT_EXAMPLE) == []
    assert all(item["findings"] == 0 for item in manager.diagnostics())

    near_matches = (
        "<APG:v1:pii:..>",
        "<APG:v1:pii:....>",
        "<APG:v1:pii:...x>",
        "<APG:v1:path:...>",
        "<APG:...>",
    )
    for value in near_matches:
        assert manager.scan(value), value


def test_example_does_not_hide_real_secrets_or_signed_placeholders(redactor) -> None:
    session_id = "sess_example"
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0"
    sanitized, events = redactor.sanitize_text(
        f"format {APG_PLACEHOLDER_FORMAT_EXAMPLE}; use {secret}",
        session_id,
    )

    assert APG_PLACEHOLDER_FORMAT_EXAMPLE in sanitized
    assert secret not in sanitized
    assert len(events) == 1
    real_placeholder = PLACEHOLDER_RE.search(sanitized)
    assert real_placeholder is not None
    assert real_placeholder.group(0) != APG_PLACEHOLDER_FORMAT_EXAMPLE

    materialized, materialization_events = redactor.materialize_local_text_with_events(sanitized, session_id)
    assert APG_PLACEHOLDER_FORMAT_EXAMPLE in materialized
    assert secret in materialized
    assert len(materialization_events) == 1
    event = materialization_events[0]
    assert {key: event[key] for key in ("type", "kind", "sink", "action", "result_code")} == {
        "type": "materialization",
        "kind": "secret",
        "sink": "local_tool",
        "action": "materialize",
        "result_code": "OK",
    }
    assert event["_audit_operation"]["direction"] == "materialization"


@pytest.mark.parametrize("split", range(len(APG_PLACEHOLDER_FORMAT_EXAMPLE) + 1))
def test_balanced_stream_preserves_example_at_every_split(redactor, split: int) -> None:
    scanner = BalancedStreamScanner(redactor, "sess_example_stream")
    first, first_events = scanner.feed(APG_PLACEHOLDER_FORMAT_EXAMPLE[:split])
    second, second_events = scanner.feed(APG_PLACEHOLDER_FORMAT_EXAMPLE[split:])
    tail, tail_events = scanner.flush()

    assert first + second + tail == APG_PLACEHOLDER_FORMAT_EXAMPLE
    assert first_events + second_events + tail_events == []


def test_stream_preserves_example_and_restores_real_placeholder(redactor) -> None:
    session_id = "sess_example_and_real"
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0"
    real_placeholder, _ = redactor.sanitize_text(secret, session_id)
    scanner = BalancedStreamScanner(redactor, session_id)

    output, events = scanner.feed(f"{APG_PLACEHOLDER_FORMAT_EXAMPLE} {real_placeholder}")
    tail, tail_events = scanner.flush()
    combined = output + tail

    assert APG_PLACEHOLDER_FORMAT_EXAMPLE in combined
    assert real_placeholder not in combined
    assert secret in combined
    assert PROTECTED_VALUE not in combined
    assert events + tail_events


def test_stream_ignores_example_even_if_old_state_stored_it_as_a_secret(redactor) -> None:
    session_id = "sess_reserved_old_state"
    redactor.mapping_store.upsert_mapping(
        session_id=session_id,
        workspace_id="ws",
        scope="request",
        kind="secret",
        subtype="legacy_value",
        value=APG_PLACEHOLDER_FORMAT_EXAMPLE,
        store_value=True,
        materialization_class="secret",
        ttl_seconds=1800,
    )
    scanner = BalancedStreamScanner(redactor, session_id)

    output, events = scanner.feed(APG_PLACEHOLDER_FORMAT_EXAMPLE)
    tail, tail_events = scanner.flush()

    assert output + tail == APG_PLACEHOLDER_FORMAT_EXAMPLE
    assert events + tail_events == []


def test_incomplete_example_is_not_exempt_from_fail_closed_streaming(redactor) -> None:
    scanner = BalancedStreamScanner(redactor, "sess_incomplete_example")
    scanner.feed(APG_PLACEHOLDER_FORMAT_EXAMPLE[:-1])
    output, events = scanner.flush()

    assert output == PROTECTED_VALUE
    assert events[-1]["subtype"] == "incomplete_stream_candidate"
