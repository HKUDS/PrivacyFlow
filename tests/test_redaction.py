from __future__ import annotations

import json
from pathlib import Path

from gateway.detector_manager import DetectorManager
from gateway.detectors.rules import builtin_rules
from gateway.mapping_store import MappingStore
from gateway.path_alias_manager import PathAliasManager
from gateway.placeholder_parser import PLACEHOLDER_RE, PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import RedactionEngine


def test_api_key_redacted_before_upstream(redactor) -> None:
    body = {"messages": [{"content": "use sk-proj-abcdefghijklmnopqrstuvwxyz123456"}]}
    sanitized, events = redactor.sanitize_json(body, "sess_1")
    text = json.dumps(sanitized)
    assert "sk-proj-" not in text
    assert "<APG:v1:secret:" in text
    assert events[0]["subtype"] == "api_key"


def test_placeholder_is_stable_after_restart_and_request_replay(redactor) -> None:
    raw = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    first, _ = redactor.sanitize_text(raw, "sess_stable")
    match = PLACEHOLDER_RE.search(first)
    assert match is not None
    record = redactor.mapping_store.get(match.group("handle"))
    assert record is not None

    signer = PlaceholderSigner("test-secret", "ws")
    restarted = RedactionEngine(
        DetectorManager(),
        MappingStore(redactor.mapping_store.path),
        signer,
        PolicyEngine(),
        "ws",
    )
    second, _ = restarted.sanitize_text(raw, "sess_stable")
    assert second == first

    replayed, replay_events = restarted.sanitize_text(first, "sess_stable")
    assert replayed == first
    assert replayed.count("<APG:v1:") == 1
    assert replay_events[0]["action"] == "preserve"

    previous_valid_form = signer.issue("secret", record.handle_id, "sess_stable", record.created_at + 1)
    canonicalized, canonical_events = restarted.sanitize_text(previous_valid_form, "sess_stable")
    assert canonicalized == first
    assert canonical_events[0]["action"] == "canonicalize"


def test_env_assignment_preserves_key_and_redacts_only_value(redactor) -> None:
    sanitized, _ = redactor.sanitize_text(
        "SERVICE_TOKEN=sk-apgtest-stream-agent-secret-2026",
        "sess_1",
    )
    assert sanitized.startswith("SERVICE_TOKEN=<APG:v1:secret:")
    assert "sk-apgtest" not in sanitized

    exported_source = 'export SERVICE_TOKEN="svc_apgtest_live_agent_2026_abcdefghijklmnopqrstuvwxyz"'
    exported, _ = redactor.sanitize_text(exported_source, "sess_1")
    assert exported.startswith('export SERVICE_TOKEN="<APG:v1:secret:')
    assert exported.endswith('>"')
    assert "svc_apgtest" not in exported
    assert redactor.materialize_local_text(exported, "sess_1") == exported_source

    read_output, _ = redactor.sanitize_text(
        '    42\u2192export SERVICE_TOKEN="svc_apgtest_live_agent_2026_abcdefghijklmnopqrstuvwxyz"',
        "sess_1",
    )
    assert read_output.startswith('    42\u2192export SERVICE_TOKEN="<APG:v1:secret:')
    assert read_output.endswith('>"')
    assert "svc_apgtest" not in read_output


def test_env_assignment_preserves_status_and_inline_log_context(redactor) -> None:
    status, status_events = redactor.sanitize_text(
        "OPENAI_API_KEY_SET=true/false",
        "sess_1",
    )
    assert status == "OPENAI_API_KEY_SET=true/false"
    assert status_events == []

    log_line, _ = redactor.sanitize_text(
        "SERVICE_TOKEN=svc_apgtest_edge_inline_55555555555555555555; retry=true; status=401",
        "sess_1",
    )
    assert log_line.startswith("SERVICE_TOKEN=<APG:v1:secret:")
    assert log_line.endswith("; retry=true; status=401")
    assert "svc_apgtest_edge_" not in log_line


def test_hex_dump_ascii_gutter_protects_split_credential_prefixes(redactor) -> None:
    source = (
        "00000020: 2e63 6f6d 2f76 312f 7265 7370 6f6e 7365  .com/v1/response\n"
        "00000080: 4b45 593d 736b 2d61 7067 7465 7374 2d33  KEY=sk-apgtest-3\n"
        "00000030: 4175 7468 6f72 697a 6174 696f 6e3a 2042  Authorization: B\n"
        "00000040: 6561 7265 7220 6579 4a68 6263 4763 694f  earer eyJhbGciO\n"
    )

    sanitized, events = redactor.sanitize_text(source, "sess_hex_dump")

    assert "sk-apgtest" not in sanitized
    assert "eyJhbGci" not in sanitized
    assert {event["subtype"] for event in events} == {"env_assignment", "jwt"}


def test_grep_path_delimiter_does_not_copy_secret_into_path_alias_or_audit_preview(redactor) -> None:
    secret = "svc_apgtest_live_agent_2026_abcdefghijklmnopqrstuvwxyz"
    source = f"/private/tmp/project/.env:SERVICE_TOKEN={secret}"

    sanitized, events = redactor.sanitize_text(source, "sess_grep")

    assert secret not in sanitized
    assert "SERVICE_TOKEN=<APG:v1:secret:" in sanitized
    assert all(secret not in str(event) for event in events)
    assert {event["subtype"] for event in events} == {"local_path", "env_assignment"}


def test_env_assignment_does_not_replace_safe_python_status_expressions(redactor) -> None:
    for source in (
        "api_key_ok = bool(OPENAI_API_KEY)",
        'OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")',
        r"api_key_ok = bool(OPENAI_API_KEY)\n",
    ):
        sanitized, events = redactor.sanitize_text(source, "sess_1")
        assert sanitized == source
        assert events == []


def test_known_value_records_are_queried_once_per_request(redactor, monkeypatch) -> None:
    store = redactor.mapping_store
    calls = 0
    original = store.active_records

    def counting(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "active_records", counting)

    # Ten string fields in one JSON body must not re-query the mapping store
    # once per field; that is O(fields x rows) and adds seconds on the large
    # requests real agents send. Exactly one query should cover all fields.
    body = {"messages": [{"content": f"plain field number {i}"} for i in range(10)]}
    redactor.sanitize_json(body, "sess_cache")
    assert calls == 1

    # Creating a new mapping bumps the store generation, so the next scan
    # rebuilds the cache (one more query) instead of serving stale records.
    redactor.sanitize_text("API_KEY=some-long-secret-value-here", "sess_cache")
    redactor.sanitize_text("nothing secret in this field", "sess_cache")
    assert calls == 2


def test_relative_suffix_fast_path_matches_pathlib() -> None:
    from pathlib import PurePosixPath, PureWindowsPath

    mgr = PathAliasManager()

    def pathlib_rel(parent: str, child: str) -> str | None:
        sep = "\\" if "\\" in parent or "\\" in child else "/"
        path_type = PureWindowsPath if sep == "\\" else PurePosixPath
        try:
            relative = path_type(child).relative_to(path_type(parent))
        except ValueError:
            return None
        if not relative.parts:
            return ""
        return "/" + "/".join(relative.parts)

    cases = [
        ("/a/b", "/a/b/c"),
        ("/a/b", "/a/b"),
        ("/a/b", "/a/bc"),
        ("/a/b/", "/a/b/c"),
        ("/a/b", "/a/b/../c"),
        ("/a", "/a/./b"),
        ("/a//b", "/a//b/c"),
        ("/b", "/a/../b"),
        ("a/b", "a/b/c"),
        ("", "/a"),
        ("/a/b", "/a/b/c/d/e"),
        ("/tmp/a", "/tmp/a-x/y"),
        ("/a/.hidden/x", "/a/.hidden/x/y"),
        ("/a/..b", "/a/..b/c"),
        ("/a", "/a/"),
        ("/a/./b", "/a/b"),
        (r"C:\Users\x", r"C:\Users\x\proj"),
    ]
    for parent, child in cases:
        assert mgr.relative_suffix(parent, child) == pathlib_rel(parent, child), (parent, child)


def test_active_path_mapping_cached_until_mapping_changes(redactor, monkeypatch) -> None:
    store = redactor.mapping_store
    calls = 0
    original = store.active_records

    def counting(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "active_records", counting)

    # Establish a path mapping, then count only the _active_path_mapping queries.
    redactor.sanitize_text("/private/tmp/one/a/path.txt", "sess_paths")
    calls = 0
    redactor._active_path_mapping("sess_paths")
    assert calls == 1  # first build queries the store
    redactor._active_path_mapping("sess_paths")
    assert calls == 1  # cached, no re-query
    # A new path mapping invalidates the cache; the next call rebuilds.
    redactor.sanitize_text("/private/tmp/two/b/path.txt", "sess_paths")
    calls = 0
    redactor._active_path_mapping("sess_paths")
    assert calls == 1  # rebuilt after the store change


def test_short_env_value_is_detected_but_not_merged_everywhere(redactor) -> None:
    assignment, events = redactor.sanitize_text("API_KEY=x", "sess_1")
    assert assignment.startswith("API_KEY=<APG:v1:secret:")
    # The single `x` now exists as an active mapping. A second scan of text
    # that merely contains `x` inside another word must not re-protect it.
    text, events = redactor.sanitize_text("expand the next extra part", "sess_1")
    assert text == "expand the next extra part"
    assert events == []


def test_materialized_secret_is_reprotected_without_original_assignment_context(redactor) -> None:
    raw = "svc_apgtest_edge_inline_55555555555555555555"
    first, _ = redactor.sanitize_text(f"SERVICE_TOKEN={raw}", "sess_1")
    materialized = redactor.materialize_local_text(first, "sess_1")

    sanitized, events = redactor.sanitize_text(f"| observed value | `{materialized.split('=', 1)[1]}` |", "sess_1")

    assert raw not in sanitized
    assert "<APG:v1:secret:" in sanitized
    assert any(event["detector"] == "known_value" for event in events)


def test_disabled_module_does_not_reprotect_existing_mapping(components) -> None:
    store, signer, policy = components
    enabled = RedactionEngine(
        DetectorManager(
            detectors_config={
                "flow": {
                    "modules": [{"id": "paths", "type": "path_detector", "enabled": True}]
                }
            }
        ),
        store,
        signer,
        policy,
        "ws",
    )
    raw = "/private/tmp/project/private/path_probe.txt"
    first, _ = enabled.sanitize_text(raw, "sess_disabled_module")
    assert raw not in first

    disabled = RedactionEngine(
        DetectorManager(
            detectors_config={
                "flow": {
                    "modules": [{"id": "paths", "type": "path_detector", "enabled": False}]
                }
            }
        ),
        store,
        signer,
        policy,
        "ws",
    )
    second, events = disabled.sanitize_text(raw, "sess_disabled_module")
    assert second == raw
    assert events == []


def test_disabled_rule_does_not_reprotect_existing_mapping(components) -> None:
    store, signer, policy = components
    raw = "custom-secret-value-1234567890"

    def manager(enabled: bool) -> DetectorManager:
        return DetectorManager(
            detectors_config={
                "flow": {
                    "modules": [
                        {
                            "id": "custom_rules",
                            "type": "regex_rules",
                            "rules": [
                                {
                                    "id": "custom.secret",
                                    "pattern": r"custom-secret-value-[0-9]+",
                                    "type": "MACHINE_SECRET",
                                    "subtype": "custom_secret",
                                    "risk": "high",
                                    "suggested_action": "redact",
                                    "enabled": enabled,
                                }
                            ],
                        }
                    ]
                }
            }
        )

    active = RedactionEngine(manager(True), store, signer, policy, "ws")
    first, _ = active.sanitize_text(raw, "sess_disabled_rule")
    assert raw not in first

    inactive = RedactionEngine(manager(False), store, signer, policy, "ws")
    second, events = inactive.sanitize_text(raw, "sess_disabled_rule")
    assert second == raw
    assert events == []


def test_email_pseudonymized_consistently(redactor) -> None:
    a, _ = redactor.sanitize_text("howard@example.com", "sess_1")
    b, _ = redactor.sanitize_text("howard@example.com", "sess_1")
    assert a == b
    assert "howard@example.com" not in a


def test_local_path_aliased(redactor) -> None:
    sanitized, _ = redactor.sanitize_text("cd /Users/howard/private/project", "sess_1")
    assert "/Users/howard" not in sanitized
    assert "/workspace/" in sanitized


def test_local_path_alias_preserves_trailing_sentence_punctuation(redactor) -> None:
    raw_path = "/private/tmp/project/private/path_probe.txt"
    sanitized, _ = redactor.sanitize_text(f"Read {raw_path}.", "sess_1")
    assert sanitized.endswith(".")
    restored = redactor.materialize_local_text(sanitized, "sess_1")
    assert restored == f"Read {raw_path}."


def test_realistic_shell_fixtures_remain_usable_after_round_trip(redactor) -> None:
    fixture_dir = Path(__file__).parent / "fixtures"
    benign = (fixture_dir / "detector_shell_benign.txt").read_text(encoding="utf-8")
    sensitive = (fixture_dir / "detector_shell_sensitive.txt").read_text(encoding="utf-8")

    benign_result, benign_events = redactor.sanitize_text(benign, "sess_shell_benign")
    assert benign_result == benign
    assert benign_events == []

    sanitized, events = redactor.sanitize_text(sensitive, "sess_shell_sensitive")
    assert len(events) == 7
    assert "SyntheticPass649" not in sanitized
    assert 'ANTHROPIC_AUTH_TOKEN="<APG:v1:secret:' in sanitized
    assert redactor.materialize_local_text(sanitized, "sess_shell_sensitive") == sensitive


def test_same_basename_paths_get_distinct_aliases(redactor) -> None:
    a, _ = redactor.sanitize_text("repo /private/tmp/a/repo", "sess_1")
    b, _ = redactor.sanitize_text("repo /private/tmp/b/repo", "sess_1")
    assert a != b
    assert "/private/tmp" not in a + b


def test_child_path_reuses_existing_parent_alias(redactor) -> None:
    root = "/private/tmp/project/apg-agent-test-repo"
    root_alias, _ = redactor.sanitize_text(root, "sess_1")
    child_alias, replacement_events = redactor.sanitize_text(root + "/scripts/validate_secret.py", "sess_1")
    assert child_alias == root_alias + "/scripts/validate_secret.py"
    restored, materialization_events = redactor.materialize_local_text_with_events(
        child_alias,
        "sess_1",
        tool_name="Read",
    )
    assert restored == root + "/scripts/validate_secret.py"
    replacement = replacement_events[-1]["_audit_operation"]
    materialization = materialization_events[-1]["_audit_operation"]
    assert replacement["alias"] == child_alias
    assert materialization["alias"] == child_alias
    assert replacement["handle_id"] == materialization["handle_id"]
    assert materialization["tool_name"] == "Read"


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


def test_active_path_mapping_uses_one_store_snapshot(redactor, monkeypatch) -> None:
    session_id = "sess_path_snapshot"
    for index in range(150):
        redactor.mapping_store.upsert_mapping(
            session_id=session_id,
            workspace_id="ws",
            scope="workspace",
            kind="path",
            subtype="local_path",
            value=f"/private/tmp/project-{index}",
            store_value=True,
            materialization_class="path",
        )

    original = redactor.mapping_store.active_records
    calls = 0

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(redactor.mapping_store, "active_records", counted)
    mapping = redactor._active_path_mapping(session_id)

    assert len(mapping) == 150
    assert calls == 1


def test_local_json_scan_reuses_path_mapping_for_all_strings(redactor, monkeypatch) -> None:
    session_id = "sess_response_snapshot"
    redactor.sanitize_text("/private/tmp/response-project", session_id)

    original = redactor._active_path_mapping
    calls = 0

    def counted(request_session_id):
        nonlocal calls
        calls += 1
        return original(request_session_id)

    monkeypatch.setattr(redactor, "_active_path_mapping", counted)
    payload = {"output": [{"content": [{"text": f"plain fragment {index}"}]} for index in range(500)]}
    scanned, events = redactor.scan_local_json(payload, session_id)

    assert scanned == payload
    assert events == []
    assert calls == 1


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


def test_local_model_only_scans_content_fields_while_rules_cover_tool_schema(components) -> None:
    store, signer, policy = components
    model_inputs: list[str] = []

    def model_runner(_adapter, _model_name, _device, text, **_options):
        model_inputs.append(text)
        return []

    manager = DetectorManager(
        detectors_config={
            "flow": {
                "id": "content_aware",
                "modules": [
                    {
                        "id": "rules",
                        "type": "regex_rules",
                        "rules": [rule.__dict__ for rule in builtin_rules()],
                    },
                    {
                        "id": "personal_model",
                        "type": "local_model",
                        "model_name": "example/pii",
                        "adapter": "transformers_token_classification",
                    },
                ],
            },
            "model_runner": model_runner,
        }
    )
    redactor = RedactionEngine(manager, store, signer, policy, "ws")
    body = {
        "model": "example-model",
        "metadata": {"trace": "sk-proj-abcdefghijklmnopqrstuvwxyz123456"},
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "read",
                    "description": "Never expose sk-proj-abcdefghijklmnopqrstuvwxyz123456",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string", "description": "Local path"}},
                    },
                },
            }
        ],
        "messages": [{"role": "user", "content": "Hello Alice"}],
    }

    sanitized, _ = redactor.sanitize_json(body, "sess_content_aware")

    assert model_inputs == ["Hello Alice"]
    assert "sk-proj-" not in json.dumps(sanitized)
    diagnostics = manager.diagnostics()
    assert [item["id"] for item in diagnostics] == ["rules", "personal_model"]
    assert diagnostics[-1]["status"] == "ok"
