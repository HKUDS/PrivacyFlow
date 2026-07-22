from __future__ import annotations

import json
from pathlib import Path

from e2e_agent_tests.scripts.check_leaks import scan_paths
from e2e_agent_tests.scripts.common import HarnessPaths
from e2e_agent_tests.scripts.run_scenario import run_scenario
from e2e_agent_tests.scripts.setup_test_repo import setup_test_repo
from e2e_agent_tests.scripts.run_live_agents import (
    LIVE_SCENARIOS,
    _agent_command,
    _contains_non_example_apg_marker,
    _extract_final_output,
    _extract_tool_summary,
    _server_environment,
    _streams_are_safe,
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
    assert "sk-apgtest" in (repo / ".env").read_text()


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


def test_live_marker_check_ignores_only_the_reserved_format_example() -> None:
    assert not _contains_non_example_apg_marker("format: <APG:v1:pii:...>")
    assert _contains_non_example_apg_marker("format: <APG:v1:pii:....>")
    assert _contains_non_example_apg_marker("shorthand: <APG:...>")
    assert _contains_non_example_apg_marker(
        "real: <APG:v1:secret:handle:session:123:AAAAAAAAAAAAAAAA>"
    )


def test_live_agent_commands_pin_the_isolated_workspace(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "provider-key-must-not-reach-agent")
    monkeypatch.setenv("UNRELATED_SECRET", "also-must-not-reach-agent")
    run_root = tmp_path / "run"
    (run_root / "apg-agent-test-repo").mkdir(parents=True)
    claude_command, claude_env = _agent_command("claude", "task", 8765, run_root)
    assert claude_env["PWD"] == str(run_root / "apg-agent-test-repo")
    assert "DEEPSEEK_API_KEY" not in claude_env
    assert "UNRELATED_SECRET" not in claude_env
    assert "--verbose" in claude_command
    assert "bypassPermissions" not in claude_command
    assert claude_command[claude_command.index("--permission-mode") + 1] == "dontAsk"
    assert claude_command[claude_command.index("--setting-sources") + 1] == "project,local"
    settings = json.loads((run_root / "claude-settings.json").read_text())
    assert settings["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8765"

    opencode_command, opencode_env = _agent_command("opencode", "task", 8765, run_root)
    assert opencode_env["PWD"] == str(run_root / "apg-agent-test-repo")
    assert "DEEPSEEK_API_KEY" not in opencode_env
    assert "UNRELATED_SECRET" not in opencode_env
    assert "--pure" in opencode_command
    assert opencode_command[opencode_command.index("--dir") + 1] == str(run_root / "apg-agent-test-repo")


def test_live_server_bypasses_system_proxy_only_for_its_upstream(monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "provider-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("APG_UPSTREAM_BASE_URL", "https://provider.example/v1")

    server_env = _server_environment()
    assert server_env["DEEPSEEK_API_KEY"] == "provider-key"
    assert server_env["NO_PROXY"] == "provider.example,127.0.0.1,localhost"
    assert server_env["no_proxy"] == server_env["NO_PROXY"]
    assert "HTTPS_PROXY" not in server_env


def test_live_agent_matrix_covers_real_read_tool_path_and_write_workflows() -> None:
    assert len(LIVE_SCENARIOS) == 11
    assert {
        "secret_tool",
        "pii_tool",
        "parallel_materialization",
        "config_debug",
        "log_analysis",
        "path_alias",
        "multi_file_review",
        "safe_env_example",
        "sanitized_customer_reply",
        "safe_debug_script",
    }.issubset(LIVE_SCENARIOS)
    assert LIVE_SCENARIOS["safe_env_example"].allow_write is True
    assert LIVE_SCENARIOS["path_alias"].required_read_paths == ("private/path_probe.txt",)


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


def test_live_agent_write_permissions_are_scenario_scoped(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    (run_root / "apg-agent-test-repo").mkdir(parents=True)
    read_command, _ = _agent_command("claude", "task", 8765, run_root, "pii_summary")
    write_command, _ = _agent_command("claude", "task", 8765, run_root, "safe_env_example")
    assert "Edit" not in read_command[read_command.index("--tools") + 1]
    assert "Edit" in write_command[write_command.index("--tools") + 1]

    _agent_command("opencode", "task", 8765, run_root, "pii_summary")
    config = json.loads((run_root / "xdg-config/opencode/opencode.json").read_text())
    assert config["permission"]["edit"] == "deny"
    _agent_command("opencode", "task", 8765, run_root, "safe_env_example")
    config = json.loads((run_root / "xdg-config/opencode/opencode.json").read_text())
    assert config["permission"]["edit"] == "allow"


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


def test_live_stream_status_allows_audited_client_cancellation() -> None:
    completed = {"parse_errors": 0, "termination": "completed"}
    disconnected = {"parse_errors": 0, "termination": "client_disconnected"}
    assert _streams_are_safe([completed, disconnected]) is True
    assert _streams_are_safe([disconnected]) is False
    assert _streams_are_safe([completed, {"parse_errors": 1, "termination": "protocol_error"}]) is False
