from __future__ import annotations

import argparse
import json
import os
import threading
import time
from pathlib import Path

import pytest

from e2e_agent_tests.scripts.check_leaks import scan_paths
from e2e_agent_tests.scripts.common import HarnessPaths
from e2e_agent_tests.scripts.export_live_evidence import (
    _claude_transcript,
    _opencode_transcript,
    _operation_annotations,
    _sanitize_export_value,
)
from e2e_agent_tests.scripts.run_scenario import run_scenario
from e2e_agent_tests.scripts.setup_test_repo import setup_test_repo
from gateway.mapping_store import MappingStore
from e2e_agent_tests.scripts.run_live_agents import (
    LIVE_SCENARIOS,
    _apply_live_launcher_config,
    _agent_command,
    _audit_operation_evidence,
    _contains_non_example_pf_marker,
    _extract_final_output,
    _extract_tool_summary,
    _extract_tool_trace,
    incompatible_agents,
    _nonnegative_int,
    _positive_int,
    _run_live_matrix,
    _server_environment,
    _streams_are_safe,
    _successful_validator_outputs,
    _validate_debug_script,
    detect_live_prerequisites,
)


STRONG_SET = [
    "scenario_01",
    "scenario_02",
    "scenario_03",
    "scenario_12",
    "scenario_14",
    "scenario_15",
    "scenario_16",
    "scenario_17",
]


def test_setup_test_repo_creates_expected_files(tmp_path: Path) -> None:
    repo = setup_test_repo(tmp_path / "repo")
    assert (repo / ".env").exists()
    assert (repo / "src/client.py").exists()
    assert (repo / "scripts/validate_pii.py").exists()
    assert (repo / "private/path_probe.txt").read_text().startswith("PATH_ALIAS_OK")
    assert "CASE-731" in (repo / "docs/customer_notes.md").read_text()
    assert "sk-pftest" in (repo / ".env").read_text()
    assert "OPENAI_API_KEY_SET=false" in (repo / "config/edge.env").read_text()
    assert "status=401" in (repo / "logs/assignment_edge.log").read_text()


def test_strong_e2e_scenarios_pass_without_canary_leaks(tmp_path: Path) -> None:
    for scenario_id in STRONG_SET:
        workdir = tmp_path / scenario_id
        result = run_scenario(scenario_id, workdir=workdir, reset=True)
        assert result["passed"], result
        paths = HarnessPaths(workdir)
        assert scan_paths([paths.upstream_log, paths.audit_log, paths.external_sink_log, paths.memory_log]) == {}


def test_all_scenario_specs_exist() -> None:
    scenarios = sorted((Path(__file__).resolve().parents[1] / "scenarios").glob("scenario_*.yaml"))
    assert len(scenarios) == 14


def test_live_agent_prerequisites_report_missing_key(monkeypatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    missing = detect_live_prerequisites([])
    assert missing == ["DEEPSEEK_API_KEY"]


def test_live_agents_require_native_matching_upstream_protocols() -> None:
    assert incompatible_agents(["opencode"], "openai_chat_completions") == []
    assert incompatible_agents(["claude"], "anthropic_messages") == []
    assert incompatible_agents(["claude", "opencode"], "openai_chat_completions") == ["claude"]
    assert incompatible_agents(["claude", "opencode"], "anthropic_messages") == ["opencode"]


def test_live_runner_can_load_active_launcher_profile_without_printing_key(
    monkeypatch,
    tmp_path: Path,
) -> None:
    launcher = tmp_path / "launcher.json"
    launcher.write_text(
        json.dumps(
            {
                "signing_secret": "local-signing-secret",
                "local_api_key": "local-agent-key",
                "active_upstream_profile_id": "up_test",
                "upstream_profiles": [
                    {
                        "id": "up_test",
                        "name": "Live test",
                        "protocol": "openai_chat_completions",
                        "base_url": "https://provider.example/v1",
                        "api_key": "provider-key-from-launcher",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    launcher.chmod(0o600)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("PF_UPSTREAM_BASE_URL", raising=False)
    monkeypatch.delenv("PF_UPSTREAM_PROTOCOL", raising=False)

    _apply_live_launcher_config(launcher)

    assert detect_live_prerequisites([]) == []
    assert os.environ["DEEPSEEK_API_KEY"] == "provider-key-from-launcher"
    assert os.environ["PF_UPSTREAM_BASE_URL"] == "https://provider.example/v1"
    assert os.environ["PF_UPSTREAM_PROTOCOL"] == "openai_chat_completions"


def test_live_matrix_runs_concurrently_preserves_order_and_isolates_failures(
    monkeypatch,
    tmp_path: Path,
) -> None:
    state = {"active": 0, "maximum": 0}
    lock = threading.Lock()

    def fake_case(agent: str, scenario: str, base: Path, timeout: float) -> dict:
        assert base == tmp_path
        assert timeout == 12.0
        with lock:
            state["active"] += 1
            state["maximum"] = max(state["maximum"], state["active"])
        try:
            time.sleep(0.03 if scenario == "slow" else 0.01)
            if scenario == "broken":
                raise RuntimeError("synthetic failure")
            return {"agent": agent, "scenario": scenario, "passed": True}
        finally:
            with lock:
                state["active"] -= 1

    monkeypatch.setattr(
        "e2e_agent_tests.scripts.run_live_agents.run_live_case",
        fake_case,
    )

    results = _run_live_matrix(
        ["claude", "opencode"],
        ["slow", "broken"],
        tmp_path,
        timeout=12.0,
        concurrency=3,
    )

    assert [(item["agent"], item["scenario"]) for item in results] == [
        ("claude", "slow"),
        ("claude", "broken"),
        ("opencode", "slow"),
        ("opencode", "broken"),
    ]
    assert state["maximum"] == 3
    assert results[0]["passed"] is True
    assert results[1]["passed"] is False
    assert "RuntimeError: synthetic failure" in results[1]["run_error"]
    assert results[2]["passed"] is True
    assert results[3]["passed"] is False


def test_live_concurrency_requires_a_positive_integer() -> None:
    assert _positive_int("1") == 1
    assert _positive_int("8") == 8
    for value in ("0", "-1", "many"):
        with pytest.raises(argparse.ArgumentTypeError, match="positive integer"):
            _positive_int(value)


def test_live_retries_accepts_zero_or_positive_integer() -> None:
    assert _nonnegative_int("0") == 0
    assert _nonnegative_int("2") == 2
    for value in ("-1", "many"):
        with pytest.raises(argparse.ArgumentTypeError, match="non-negative integer"):
            _nonnegative_int(value)


def test_live_matrix_retries_only_failed_cases(monkeypatch, tmp_path: Path) -> None:
    attempts: dict[tuple[str, str], int] = {}

    def flaky_case(agent: str, scenario: str, base: Path, timeout: float) -> dict:
        key = (agent, scenario)
        attempts[key] = attempts.get(key, 0) + 1
        return {
            "agent": agent,
            "scenario": scenario,
            "passed": attempts[key] >= 2,
        }

    monkeypatch.setattr(
        "e2e_agent_tests.scripts.run_live_agents.run_live_case",
        flaky_case,
    )

    results = _run_live_matrix(
        ["claude"],
        ["flaky"],
        tmp_path,
        timeout=12.0,
        concurrency=1,
        retries=1,
    )

    assert results == [
        {
            "agent": "claude",
            "scenario": "flaky",
            "passed": True,
            "attempt_count": 2,
        }
    ]
    assert attempts == {("claude", "flaky"): 2}


def test_live_agent_final_output_excludes_tool_trajectory() -> None:
    claude = '\n'.join([
        '{"type":"assistant","tool":{"arguments":"raw-secret"}}',
        '{"type":"result","result":"safe final"}',
    ])
    assert _extract_final_output("claude", claude) == "safe final"
    opencode = '\n'.join([
        '{"part":{"type":"tool","state":{"input":"raw-secret"}}}',
        '{"part":{"type":"text","text":"safe final"}}',
    ])
    assert _extract_final_output("opencode", opencode) == "safe final"


def test_live_marker_check_ignores_all_reserved_format_examples() -> None:
    assert not _contains_non_example_pf_marker("format: <PF:v1:pii:...>")
    assert not _contains_non_example_pf_marker("format: <PF:v1:secret:...>")
    assert _contains_non_example_pf_marker("format: <PF:v1:pii:....>")
    assert _contains_non_example_pf_marker("shorthand: <PF:...>")
    assert _contains_non_example_pf_marker(
        "real: <PF:v1:secret:handle:session:123:AAAAAAAAAAAAAAAA>"
    )


def test_live_agent_commands_pin_the_isolated_workspace(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "provider-key-must-not-reach-agent")
    monkeypatch.setenv("UNRELATED_SECRET", "also-must-not-reach-agent")
    monkeypatch.setenv("PF_LIVE_MODEL", "gpt-5.6-terra")
    run_root = tmp_path / "run"
    (run_root / "pf-agent-test-repo").mkdir(parents=True)
    claude_command, claude_env = _agent_command("claude", "task", 8765, run_root)
    assert claude_env["PWD"] == str(run_root / "pf-agent-test-repo")
    assert "DEEPSEEK_API_KEY" not in claude_env
    assert "UNRELATED_SECRET" not in claude_env
    assert claude_env["HTTPS_PROXY"] == "http://127.0.0.1:9"
    assert claude_env["NO_PROXY"] == "127.0.0.1,localhost"
    assert "--verbose" in claude_command
    assert "bypassPermissions" not in claude_command
    assert claude_command[claude_command.index("--permission-mode") + 1] == "dontAsk"
    assert claude_command[claude_command.index("--setting-sources") + 1] == "project,local"
    assert claude_command[claude_command.index("--model") + 1] == "gpt-5.6-terra"
    settings = json.loads((run_root / "claude-settings.json").read_text())
    assert settings["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8765"
    assert settings["env"]["ANTHROPIC_AUTH_TOKEN"] == "pf-local"
    assert "ANTHROPIC_API_KEY" not in settings["env"]
    assert "ANTHROPIC_API_KEY" not in claude_env

    opencode_command, opencode_env = _agent_command("opencode", "task", 8765, run_root)
    assert opencode_env["PWD"] == str(run_root / "pf-agent-test-repo")
    assert "DEEPSEEK_API_KEY" not in opencode_env
    assert "UNRELATED_SECRET" not in opencode_env
    assert opencode_env["HTTPS_PROXY"] == "http://127.0.0.1:9"
    assert "--pure" in opencode_command
    assert opencode_command[opencode_command.index("--dir") + 1] == str(run_root / "pf-agent-test-repo")
    assert opencode_command[opencode_command.index("--model") + 1] == "pf/gpt-5.6-terra"
    opencode_config = json.loads((run_root / "xdg-config/opencode/opencode.json").read_text())
    assert opencode_config["model"] == "pf/gpt-5.6-terra"
    assert list(opencode_config["provider"]["pf"]["models"]) == ["gpt-5.6-terra"]


def test_live_server_bypasses_system_proxy_only_for_its_upstream(monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "provider-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("PF_UPSTREAM_BASE_URL", "https://provider.example/v1")

    server_env = _server_environment()
    assert server_env["DEEPSEEK_API_KEY"] == "provider-key"
    assert server_env["NO_PROXY"] == "provider.example,127.0.0.1,localhost"
    assert server_env["no_proxy"] == server_env["NO_PROXY"]
    assert "HTTPS_PROXY" not in server_env

    no_entropy_env = _server_environment(disable_entropy=True)
    assert no_entropy_env["PF_LIVE_DISABLE_ENTROPY"] == "1"


def test_live_agent_matrix_uses_natural_tasks_and_covers_write_workflows(tmp_path: Path) -> None:
    assert len(LIVE_SCENARIOS) == 15
    assert {
        "secret_tool",
        "pii_tool",
        "parallel_materialization",
        "config_debug",
        "log_analysis",
        "path_alias",
        "multi_file_review",
        "safe_env_example",
        "exact_sensitive_copy",
        "sanitized_customer_reply",
        "safe_debug_script",
        "status_literal_doc",
        "edge_credential_inventory",
        "inline_assignment_log",
    }.issubset(LIVE_SCENARIOS)
    assert LIVE_SCENARIOS["exact_sensitive_copy"].disable_entropy is True
    assert LIVE_SCENARIOS["exact_sensitive_copy"].exact_copy_pairs
    assert {"api key", "openai_api_key"}.issubset(LIVE_SCENARIOS["log_analysis"].required_final_any)
    for scenario in LIVE_SCENARIOS.values():
        prompt = scenario.prompt(tmp_path) if callable(scenario.prompt) else scenario.prompt
        lowered = prompt.lower()
        for prescriptive_phrase in ("read tool", "edit tool", "write tool", "bash", "do not", "don't", "never"):
            assert prescriptive_phrase not in lowered


def test_live_agent_tool_summary_omits_materialized_arguments(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    claude = json.dumps(
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "read-1",
                        "name": "Read",
                        "input": {"file_path": str(repo / ".env")},
                    },
                    {
                        "type": "tool_use",
                        "id": "bash-1",
                        "name": "Bash",
                        "input": {"command": "python scripts/validate_secret.py raw-secret"},
                    },
                ]
            },
        }
    )
    summary = _extract_tool_summary("claude", claude, repo)
    assert summary == {"counts": {"bash": 1, "read": 1}, "file_paths": [".env"]}
    assert "raw-secret" not in json.dumps(summary)


def test_live_agent_tool_trace_is_ordered_and_omits_materialized_arguments(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    events = "\n".join(
        [
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "tool_use", "id": "read-1", "name": "Read", "input": {"file_path": str(repo / ".env")}},
                            {
                                "type": "tool_use",
                                "id": "bash-1",
                                "name": "Bash",
                                "input": {"command": "python scripts/validate_secret.py raw-secret"},
                            },
                        ]
                    },
                }
            )
        ]
    )
    trace = _extract_tool_trace("claude", events, repo)
    assert trace == [
        {"step": 1, "tool": "read", "target": ".env"},
        {"step": 2, "tool": "bash", "target": "scripts/validate_secret.py"},
    ]
    assert "raw-secret" not in json.dumps(trace)


def test_live_agent_accepts_successful_validator_output_after_agent_cleanup() -> None:
    event = {
        "type": "tool_use",
        "part": {
            "tool": "bash",
            "state": {
                "status": "completed",
                "output": "VALIDATOR_OK\n",
                "metadata": {"exit": 0},
            },
        },
    }
    assert _successful_validator_outputs("opencode", json.dumps(event)) == {"validator_success.json"}

    failed = {
        "type": "tool_use",
        "part": {
            "tool": "bash",
            "state": {
                "status": "completed",
                "output": "VALIDATOR_FAILED\n",
                "metadata": {"exit": 1},
            },
        },
    }
    assert _successful_validator_outputs("opencode", json.dumps(failed)) == set()


def test_claude_validator_success_must_come_from_bash_result() -> None:
    bash_call = {
        "type": "assistant",
        "message": {
            "content": [
                {"type": "tool_use", "id": "bash-1", "name": "Bash", "input": {"command": "omitted"}},
                {"type": "tool_use", "id": "read-1", "name": "Read", "input": {"file_path": "note.txt"}},
            ]
        },
    }
    results = {
        "type": "user",
        "message": {
            "content": [
                {"type": "tool_result", "tool_use_id": "read-1", "content": "VALIDATOR_OK"},
                {"type": "tool_result", "tool_use_id": "bash-1", "content": "PII_VALIDATOR_OK"},
            ]
        },
    }
    stdout = "\n".join((json.dumps(bash_call), json.dumps(results)))
    assert _successful_validator_outputs("claude", stdout) == {"pii_validator_success.json"}


def test_live_agents_receive_uniform_local_tool_permissions(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    (run_root / "pf-agent-test-repo").mkdir(parents=True)
    claude_command, _ = _agent_command("claude", "task", 8765, run_root)
    tools = set(claude_command[claude_command.index("--tools") + 1].split(","))
    allowed = set(claude_command[claude_command.index("--allowedTools") + 1].split(","))
    assert tools == {"Read", "Glob", "Grep", "Edit", "Write", "Bash"}
    assert allowed == tools

    _agent_command("opencode", "task", 8765, run_root)
    config = json.loads((run_root / "xdg-config/opencode/opencode.json").read_text())
    assert config["permission"]["edit"] == "allow"
    assert config["permission"]["bash"] == "allow"
    assert config["permission"]["webfetch"] == "deny"
    assert config["permission"]["external_directory"] == "deny"


def test_live_evidence_keeps_claude_visible_text_and_tool_io(tmp_path: Path) -> None:
    trajectory = tmp_path / "trajectory.jsonl"
    events = [
        {
            "type": "assistant",
            "timestamp": "2026-07-23T00:00:00Z",
            "message": {
                "content": [
                    {"type": "text", "text": "I will inspect the file."},
                    {"type": "tool_use", "id": "call-1", "name": "Read", "input": {"file_path": ".env"}},
                ]
            },
        },
        {
            "type": "user",
            "message": {
                "content": [
                    {"type": "tool_result", "tool_use_id": "call-1", "content": "SERVICE_TOKEN=fake"}
                ]
            },
        },
    ]
    trajectory.write_text("\n".join(json.dumps(event) for event in events))
    transcript = _claude_transcript(trajectory)
    assert [item["kind"] for item in transcript] == ["assistant", "tool_call", "tool_result"]
    assert transcript[1]["input"] == '{\n  "file_path": ".env"\n}'
    assert transcript[2]["output"] == "SERVICE_TOKEN=fake"


def test_live_evidence_keeps_opencode_tool_input_output_and_reasoning_count(tmp_path: Path) -> None:
    trajectory = tmp_path / "trajectory.jsonl"
    events = [
        {
            "type": "tool_use",
            "part": {
                "tool": "bash",
                "callID": "call-1",
                "state": {"status": "completed", "input": {"command": "echo fake"}, "output": "fake"},
            },
        },
        {
            "type": "step_finish",
            "part": {
                "reason": "tool-calls",
                "tokens": {"input": 10, "output": 2, "reasoning": 3, "cache": {"read": 4}},
            },
        },
    ]
    trajectory.write_text("\n".join(json.dumps(event) for event in events))
    transcript = _opencode_transcript(trajectory)
    assert transcript[0]["input"] == '{\n  "command": "echo fake"\n}'
    assert transcript[0]["output"] == "fake"
    assert transcript[1]["data"]["reasoning_tokens"] == 3


def test_live_evidence_exports_exact_audited_replacement_and_materialization(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    store = MappingStore(str(artifacts / "pf_proxy_state.sqlite3"), namespace="PF")
    mapping = store.upsert_mapping(
        session_id="sess_local",
        workspace_id="ws",
        scope="request",
        kind="secret",
        subtype="api_key",
        value="sk-pftest-evidence-value",
        store_value=True,
        materialization_class="tool_arg",
    )
    placeholder = f"<PF:v1:secret:{mapping.handle_id}:sess_local:123:signature>"
    (artifacts / "upstream_requests.jsonl").write_text(
        json.dumps({"body": {"messages": [{"content": placeholder}]}})
    )
    shared = {
        "handle_id": mapping.handle_id,
        "kind": "secret",
        "subtype": "api_key",
        "risk": "critical",
        "detector": "credential_regex",
        "representation_type": "signed_placeholder",
        "placeholder_session_id": "sess_local",
        "issued_at": 123,
        "suffix": "",
        "alias": "",
        "result_code": "OK",
    }
    store.record_audit_operations(
        request_id="req_evidence",
        session_id="sess_local",
        workspace_id="ws",
        endpoint="/v1/messages",
        timestamp=1,
        operations=[
            {**shared, "direction": "replacement", "action": "redact", "sink": "remote_llm"},
            {
                **shared,
                "direction": "materialization",
                "action": "materialize",
                "sink": "local_tool",
                "tool_name": "Bash",
            },
        ],
    )
    store.close()

    operations = _operation_annotations(str(artifacts))

    assert [(item["direction"], item["tool_name"]) for item in operations] == [
        ("materialization", "Bash"),
        ("replacement", ""),
    ]
    assert all(item["original"] == "sk-pftest-evidence-value" for item in operations)
    assert all(item["representation"] == placeholder for item in operations)
    assert all(item["request_ids"] == ["req_evidence"] for item in operations)
    assert all(item["timestamps"] == [1] for item in operations)


def test_checked_in_live_evidence_recursively_removes_protected_values_and_local_paths() -> None:
    sanitized = _sanitize_export_value({
        "fixture": "Howard Zhang has sk-pftest-111111111111111111111111111111111111",
        "operation": ["<PF:v1:secret:sec_123:session:123:signature>"],
        "source": "/private/tmp/pf-live-agents/run/agent_trajectory.txt",
        "home": "/Users/howard/Documents/code/private.txt",
        "listing": "-rw-r--r--  1 howard  wheel  42 Aug  5 10:00 evidence.txt",
    })

    serialized = json.dumps(sanitized)
    assert "Howard Zhang" not in serialized
    assert "sk-pftest" not in serialized
    assert "<PF:v1" not in serialized
    assert "/private/tmp" not in serialized
    assert "/Users/howard" not in serialized
    assert " howard  wheel " not in serialized
    assert "<local-home-path>" in serialized
    assert "<local-user>" in serialized
    assert serialized.count("<synthetic-protected-value>") == 2

    checked_in = (Path(__file__).resolve().parents[2] / "docs" / "live_agent_evidence.js").read_text()
    assert "/Users/" not in checked_in
    assert "/private/tmp" not in checked_in
    assert "/var/folders/" not in checked_in
    assert "howard" not in checked_in.lower()


def test_live_evidence_page_renders_markdown_and_inline_legacy_apg_operations() -> None:
    page = (Path(__file__).resolve().parents[2] / "docs" / "live_agent_scenarios.html").read_text()

    assert '<script src="./vendor/marked.min.js"></script>' in page
    assert "renderMarkdownWithAnnotations" in page
    assert "sanitizeMarkdownHTML" in page
    assert "↑ 上行已替换" in page
    assert "↓ 本地已还原" in page
    assert "云端保护表示" in page
    # The checked-in HTML is a historical APG capture.  The active exporter
    # emits PF, but historical generated evidence is intentionally immutable.
    assert "data-apg-toggle" in page
    assert "toggleAPGMark" in page
    assert 'data-apg-value="protected"' in page
    assert 'role="button" tabindex="0"' in page


def test_debug_script_validation_accepts_python_boolean_casing(tmp_path: Path) -> None:
    script = tmp_path / "scripts" / "debug_config.py"
    script.parent.mkdir()
    script.write_text(
        "import os\n"
        "print(f'OPENAI_API_KEY_SET={os.getenv(\"OPENAI_API_KEY\") is not None}')\n"
        "print(f'DATABASE_URL_SET={os.getenv(\"DATABASE_URL\") is not None}')\n"
        "print(f'DEBUG={os.getenv(\"DEBUG\", \"false\")}')\n"
    )
    failures, details = _validate_debug_script(script)
    assert failures == []
    assert details["stdout_safe"] is True


def test_debug_script_validation_accepts_natural_status_format(tmp_path: Path) -> None:
    script = tmp_path / "scripts" / "debug_config.py"
    script.parent.mkdir()
    script.write_text(
        "print('API Key: configured')\n"
        "print('Database URL is set')\n"
        "print('Debug mode: true')\n"
    )
    failures, details = _validate_debug_script(script)
    assert failures == []
    assert details["stdout_safe"] is True


def test_debug_script_validation_accepts_status_before_label(tmp_path: Path) -> None:
    script = tmp_path / "scripts" / "debug_config.py"
    script.parent.mkdir()
    script.write_text(
        "print('[CONFIGURED] OPENAI_API_KEY')\n"
        "print('[CONFIGURED] DATABASE_URL')\n"
        "print('Debug mode: true')\n"
    )
    failures, details = _validate_debug_script(script)
    assert failures == []
    assert details["stdout_safe"] is True


def test_debug_script_validation_accepts_database_label_without_url_suffix(tmp_path: Path) -> None:
    script = tmp_path / "scripts" / "debug_config.py"
    script.parent.mkdir()
    script.write_text(
        "print('API key: configured | Database: configured | Debug mode: true')\n"
    )
    failures, details = _validate_debug_script(script)
    assert failures == []
    assert details["stdout_safe"] is True


def test_live_stream_status_allows_audited_client_cancellation() -> None:
    completed = {"parse_errors": 0, "termination": "completed"}
    disconnected = {"parse_errors": 0, "termination": "client_disconnected"}
    assert _streams_are_safe([completed, disconnected]) is True
    assert _streams_are_safe([disconnected]) is False
    assert _streams_are_safe([completed, {"parse_errors": 1, "termination": "protocol_error"}]) is False


def test_live_audit_evidence_counts_pairs_without_exposing_identifiers(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite3"
    store = MappingStore(str(database), namespace="PF")
    shared = {
        "handle_id": "secr_internal_only",
        "kind": "secret",
        "subtype": "api_key",
        "representation_type": "signed_placeholder",
        "placeholder_session_id": "sess_internal_only",
        "issued_at": 123,
        "suffix": "",
        "alias": "",
        "result_code": "OK",
    }
    store.record_audit_operations(
        request_id="req_123456789abc",
        session_id="sess_internal_only",
        workspace_id="ws",
        endpoint="/v1/messages",
        timestamp=1,
        operations=[
            {**shared, "direction": "replacement", "action": "redact", "sink": "remote_llm"},
            {**shared, "direction": "materialization", "action": "materialize", "sink": "local_tool", "tool_name": "Write"},
            {**shared, "direction": "materialization", "action": "materialize", "sink": "local_user", "tool_name": ""},
        ],
    )
    store.close()

    evidence = _audit_operation_evidence(database)

    assert evidence["replacement_count"] == 1
    assert evidence["materialization_count"] == 2
    assert evidence["local_tool_materialization_count"] == 1
    assert evidence["local_user_materialization_count"] == 1
    assert evidence["paired_representation_unique"] == 1
    assert "secr_internal_only" not in json.dumps(evidence)
    assert "sess_internal_only" not in json.dumps(evidence)
