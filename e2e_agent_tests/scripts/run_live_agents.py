from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from e2e_agent_tests.scripts.check_leaks import scan_paths
from e2e_agent_tests.scripts.common import CANARY_STRINGS, HarnessPaths, file_snapshot, read_jsonl, reset_path, sha256_file
from e2e_agent_tests.scripts.setup_test_repo import setup_test_repo
from gateway.cli.launcher import LauncherConfigError, prepare_launcher_config
from gateway.placeholder_parser import APG_PLACEHOLDER_FORMAT_EXAMPLES
from gateway.upstream_protocol import (
    ANTHROPIC_MESSAGES,
    OPENAI_CHAT_COMPLETIONS,
    canonical_upstream_protocol,
)


PromptFactory = Callable[[Path], str]
DEFAULT_LIVE_MODEL = "deepseek-v4-flash"
AGENT_UPSTREAM_PROTOCOLS = {
    "claude": ANTHROPIC_MESSAGES,
    "opencode": OPENAI_CHAT_COMPLETIONS,
}


@dataclass(frozen=True)
class LiveScenario:
    prompt: str | PromptFactory
    validator_files: tuple[str, ...] = ()
    generated_files: tuple[str, ...] = ()
    generated_file_alternatives: tuple[tuple[str, ...], ...] = ()
    exact_copy_pairs: tuple[tuple[str, str], ...] = ()
    allow_generated_sensitive: bool = False
    disable_entropy: bool = False
    required_final_all: tuple[str, ...] = ()
    required_final_any: tuple[str, ...] = ()

def _path_alias_prompt(repo: Path) -> str:
    target = (repo / "private" / "path_probe.txt").resolve()
    return f"What marker is stored in this file? {target}"


LIVE_SCENARIOS: dict[str, LiveScenario] = {
    "secret_tool": LiveScenario(
        prompt="Can you check whether SERVICE_TOKEN in .env is accepted by scripts/validate_secret.py?",
        validator_files=("validator_success.json",),
    ),
    "pii_tool": LiveScenario(
        prompt="Please check whether the Email in docs/customer_notes.md is accepted by scripts/validate_pii.py.",
        validator_files=("pii_validator_success.json",),
    ),
    "parallel_materialization": LiveScenario(
        prompt=(
            "Please validate SERVICE_TOKEN from .env with scripts/validate_secret.py and the Email from "
            "docs/customer_notes.md with scripts/validate_pii.py."
        ),
        validator_files=("validator_success.json", "pii_validator_success.json"),
    ),
    "config_debug": LiveScenario(
        prompt="The API client is failing to connect. Please inspect .env and src/client.py and give me a concise diagnosis.",
        required_final_any=("OPENAI_API_KEY", "DATABASE_URL"),
    ),
    "pii_summary": LiveScenario(
        prompt="Please summarize the case number, issue, and next step in docs/customer_notes.md.",
        required_final_all=("CASE-731",),
        required_final_any=("retry", "timeout", "backoff"),
    ),
    "log_analysis": LiveScenario(
        prompt="Please investigate the request failure in logs/error.log and explain the likely cause and next debugging step.",
        required_final_any=("authorization", "authentication", "credential", "token", "api key", "openai_api_key"),
    ),
    "path_alias": LiveScenario(
        prompt=_path_alias_prompt,
        required_final_all=("PATH_ALIAS_OK",),
    ),
    "multi_file_review": LiveScenario(
        prompt=(
            "Review src/config.py, src/client.py, .env, logs/error.log, and docs/customer_notes.md. "
            "Give me a concise assessment of the main operational and privacy risks."
        ),
        required_final_any=("risk", "privacy", "credential", "secret"),
    ),
    "safe_env_example": LiveScenario(
        prompt="Create a .env.example based on the variables used in .env and src/config.py for new developers.",
        generated_files=(".env.example",),
    ),
    "exact_sensitive_copy": LiveScenario(
        prompt="Create copied_commands.txt as an exact backup copy of fixtures/sensitive_commands.txt.",
        generated_files=("copied_commands.txt",),
        exact_copy_pairs=(("fixtures/sensitive_commands.txt", "copied_commands.txt"),),
        allow_generated_sensitive=True,
        disable_entropy=True,
    ),
    "sanitized_customer_reply": LiveScenario(
        prompt=(
            "Draft a concise status update for CASE-731 from docs/customer_notes.md and save it as customer_reply.md. "
            "Exclude all customer names, contact details, payment details, and other personal information."
        ),
        generated_file_alternatives=(("customer_reply.md", "docs/customer_reply.md"),),
    ),
    "safe_debug_script": LiveScenario(
        prompt=(
            "Based on src/config.py, add scripts/debug_config.py that reports whether the API key and database URL "
            "are configured and shows the current debug mode. It must run successfully as "
            "`python scripts/debug_config.py` from the repository root, reporting status only without credential values."
        ),
        generated_files=("scripts/debug_config.py",),
    ),
    "status_literal_doc": LiveScenario(
        prompt=(
            "Add docs/config-status.md explaining that OPENAI_API_KEY_SET=true/false is a boolean status notation "
            "used in our runbook."
        ),
        generated_files=("docs/config-status.md",),
    ),
    "edge_credential_inventory": LiveScenario(
        prompt=(
            "Create docs/edge-config-notes.md summarizing what each setting in config/edge.env controls. "
            "Include only setting names and behavior, keeping the document free of current credential values."
        ),
        generated_files=("docs/edge-config-notes.md",),
    ),
    "inline_assignment_log": LiveScenario(
        prompt="Please diagnose the failure in logs/assignment_edge.log and suggest the next check.",
        required_final_all=("401",),
        required_final_any=("authorization", "authentication", "credential", "token"),
    ),
}

# Backward-compatible name for callers that only need the selectable scenario keys.
SCENARIO_PROMPTS = {name: scenario.prompt for name, scenario in LIVE_SCENARIOS.items()}


_ENV_ALLOWLIST = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "COLORTERM",
    "NO_COLOR",
}


def detect_live_prerequisites(agents: list[str]) -> list[str]:
    missing: list[str] = []
    if not os.getenv("DEEPSEEK_API_KEY"):
        missing.append("DEEPSEEK_API_KEY")
    for agent in agents:
        if shutil.which(agent) is None:
            missing.append(agent)
    return missing


def incompatible_agents(agents: list[str], upstream_protocol: str) -> list[str]:
    protocol = canonical_upstream_protocol(upstream_protocol)
    return [agent for agent in agents if AGENT_UPSTREAM_PROTOCOLS[agent] != protocol]


def _apply_live_launcher_config(path: Path) -> None:
    config = prepare_launcher_config(path, environ={})
    api_key = str(config.get("_resolved_upstream_api_key", "")).strip()
    base_url = str(config.get("_resolved_upstream_base_url", "")).strip()
    protocol = str(config.get("_resolved_upstream_protocol", "")).strip()
    if not api_key or not base_url or not protocol:
        raise LauncherConfigError("The active launcher upstream profile is incomplete.")
    os.environ["DEEPSEEK_API_KEY"] = api_key
    os.environ["APG_UPSTREAM_BASE_URL"] = base_url
    os.environ["APG_UPSTREAM_PROTOCOL"] = protocol


def _base_child_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key in _ENV_ALLOWLIST}


def _agent_environment(repo: Path) -> dict[str, str]:
    env = _base_child_environment()
    env.update(
        {
            "PWD": str(repo),
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        }
    )
    return env


def _server_environment(*, disable_entropy: bool = False) -> dict[str, str]:
    env = _base_child_environment()
    env["DEEPSEEK_API_KEY"] = os.environ["DEEPSEEK_API_KEY"]
    env["APG_UPSTREAM_PROTOCOL"] = os.getenv("APG_UPSTREAM_PROTOCOL", OPENAI_CHAT_COMPLETIONS)
    upstream_base_url = os.getenv("APG_UPSTREAM_BASE_URL", "https://api.deepseek.com")
    if os.getenv("APG_UPSTREAM_BASE_URL"):
        env["APG_UPSTREAM_BASE_URL"] = upstream_base_url
    upstream_host = urlparse(upstream_base_url).hostname
    no_proxy = ",".join(value for value in (upstream_host, "127.0.0.1", "localhost") if value)
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy
    env["PYTHONUNBUFFERED"] = "1"
    if disable_entropy:
        env["APG_LIVE_DISABLE_ENTROPY"] = "1"
    return env


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[str], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("APG live-agent server exited before accepting connections")
        with socket.socket() as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError("Timed out waiting for APG live-agent server")


def _live_model() -> str:
    return os.getenv("APG_LIVE_MODEL", DEFAULT_LIVE_MODEL)


def _opencode_config(config_root: Path, port: int) -> None:
    config_dir = config_root / "opencode"
    config_dir.mkdir(parents=True, exist_ok=True)
    model = _live_model()
    config = {
        "$schema": "https://opencode.ai/config.json",
        "model": f"apg/{model}",
        "provider": {
            "apg": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "APG",
                "options": {"baseURL": f"http://127.0.0.1:{port}/v1", "apiKey": "apg-local"},
                "models": {model: {"name": f"{model} through APG", "tool_call": True}},
            }
        },
        "permission": {
            "read": "allow",
            "glob": "allow",
            "grep": "allow",
            "edit": "allow",
            "webfetch": "deny",
            "external_directory": "deny",
            "bash": "allow",
        },
    }
    (config_dir / "opencode.json").write_text(json.dumps(config, indent=2), encoding="utf-8")


def _agent_command(
    agent: str,
    prompt: str,
    port: int,
    run_root: Path,
) -> tuple[list[str], dict[str, str]]:
    repo = run_root / "apg-agent-test-repo"
    env = _agent_environment(repo)
    if agent == "claude":
        settings_path = run_root / "claude-settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "env": {
                        "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}",
                        "ANTHROPIC_AUTH_TOKEN": "apg-local",
                    }
                }
            ),
            encoding="utf-8",
        )
        env.update(
            {
                "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}",
                "ANTHROPIC_AUTH_TOKEN": "apg-local",
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            }
        )
        available_tools = ["Read", "Glob", "Grep", "Edit", "Write", "Bash"]
        allowed_tools = list(available_tools)
        command = [
            "claude",
            "--bare",
            "--safe-mode",
            "--settings",
            str(settings_path),
            "--setting-sources",
            "project,local",
            "--disable-slash-commands",
            "--print",
            "--output-format",
            "stream-json",
            "--verbose",
            "--include-partial-messages",
            "--no-session-persistence",
            "--permission-mode",
            "dontAsk",
            "--tools",
            ",".join(available_tools),
            "--allowedTools",
            ",".join(allowed_tools),
            "--model",
            _live_model(),
            prompt,
        ]
        return command, env

    config_root = run_root / "xdg-config"
    data_root = run_root / "xdg-data"
    data_root.mkdir(parents=True, exist_ok=True)
    _opencode_config(config_root, port)
    env.update({"XDG_CONFIG_HOME": str(config_root), "XDG_DATA_HOME": str(data_root)})
    return [
        "opencode",
        "run",
        "--pure",
        "--dir",
        str(repo),
        "--model",
        f"apg/{_live_model()}",
        "--format",
        "json",
        prompt,
    ], env


def _payload_has_contract(event: dict[str, Any]) -> bool:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return False
    # OpenAI Responses: the contract is injected as top-level instructions.
    instructions = payload.get("instructions")
    if isinstance(instructions, str) and "Agent Privacy Gateway" in instructions:
        return True
    # Anthropic Messages: the contract is injected into the top-level system
    # field, which may be a string or a list of {type: text, text: ...} blocks.
    system = payload.get("system")
    if isinstance(system, str) and "Agent Privacy Gateway" in system:
        return True
    if isinstance(system, list):
        for block in system:
            if isinstance(block, dict) and "Agent Privacy Gateway" in str(block.get("text", "")):
                return True
    return any(
        isinstance(message, dict) and "Agent Privacy Gateway" in str(message.get("content", ""))
        for message in payload.get("messages", [])
    )


def _json_events(stdout: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _extract_final_output(agent: str, stdout: str) -> str:
    visible_parts: list[str] = []
    for event in _json_events(stdout):
        if agent == "claude" and event.get("type") == "result" and isinstance(event.get("result"), str):
            visible_parts = [event["result"]]
            continue
        part = event.get("part")
        if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
            visible_parts.append(part["text"])
        elif event.get("type") in {"text", "message"} and isinstance(event.get("text"), str):
            visible_parts.append(event["text"])
    return "\n".join(visible_parts) if visible_parts else stdout


def _workspace_relative_path(value: Any, repo: Path) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        return str(path)
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except ValueError:
        return "<outside-workspace>"


def _tool_calls(agent: str, stdout: str) -> list[tuple[str, str, Any]]:
    seen: set[str] = set()
    calls: list[tuple[str, str, Any]] = []
    for event in _json_events(stdout):
        candidates: list[tuple[str, str, Any]] = []
        if agent == "claude" and event.get("type") == "assistant":
            message = event.get("message")
            if isinstance(message, dict):
                for item in message.get("content", []):
                    if isinstance(item, dict) and item.get("type") == "tool_use":
                        candidates.append((str(item.get("id", "")), str(item.get("name", "")), item.get("input")))
        elif agent == "opencode" and event.get("type") == "tool_use":
            part = event.get("part")
            if isinstance(part, dict):
                state = part.get("state")
                tool_input = state.get("input") if isinstance(state, dict) else None
                candidates.append((str(part.get("callID", "")), str(part.get("tool", "")), tool_input))
        for call_id, name, tool_input in candidates:
            dedupe_key = call_id or f"{name}:{len(calls)}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            calls.append((call_id, name.lower(), tool_input))
    return calls


def _extract_tool_summary(agent: str, stdout: str, repo: Path) -> dict[str, Any]:
    names: list[str] = []
    file_paths: list[str] = []
    for _, normalized_name, tool_input in _tool_calls(agent, stdout):
        names.append(normalized_name)
        if normalized_name not in {"read", "write", "edit"} or not isinstance(tool_input, dict):
            continue
        for key in ("file_path", "filePath", "path"):
            normalized_path = _workspace_relative_path(tool_input.get(key), repo)
            if normalized_path:
                file_paths.append(normalized_path)
                break
    return {"counts": dict(sorted(Counter(names).items())), "file_paths": sorted(set(file_paths))}


def _extract_tool_trace(agent: str, stdout: str, repo: Path) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = []
    for _, normalized_name, tool_input in _tool_calls(agent, stdout):
        target = ""
        if isinstance(tool_input, dict):
            if normalized_name not in {"read", "write", "edit"} or not isinstance(tool_input, dict):
                if normalized_name in {"glob", "grep"}:
                    raw_path = tool_input.get("path")
                    target = _workspace_relative_path(raw_path, repo) or "query omitted"
                elif normalized_name == "bash":
                    command = str(tool_input.get("command", ""))
                    script_match = re.search(r"(?:^|[\s\"'])([A-Za-z0-9_./-]*scripts/[A-Za-z0-9_.-]+)", command)
                    if script_match:
                        target = _workspace_relative_path(script_match.group(1), repo) or "script path omitted"
                    else:
                        target = "shell command (arguments omitted)"
                elif normalized_name in {"task", "agent"}:
                    target = "subagent task (prompt omitted)"
            else:
                for key in ("file_path", "filePath", "path"):
                    normalized_path = _workspace_relative_path(tool_input.get(key), repo)
                    if normalized_path:
                        target = normalized_path
                        break
        trace.append({"step": len(trace) + 1, "tool": normalized_name or "unknown", "target": target})
    return trace


def _successful_validator_outputs(agent: str, stdout: str) -> set[str]:
    successes: set[str] = set()
    claude_bash_ids = {
        call_id
        for call_id, name, _ in _tool_calls(agent, stdout)
        if agent == "claude" and name == "bash" and call_id
    }
    for event in _json_events(stdout):
        if agent == "opencode" and event.get("type") == "tool_use":
            part = event.get("part")
            if not isinstance(part, dict):
                continue
            state = part.get("state") if isinstance(part.get("state"), dict) else {}
            if part.get("tool") != "bash" or state.get("status") != "completed":
                continue
            output = str(state.get("output", ""))
            metadata = state.get("metadata") if isinstance(state.get("metadata"), dict) else {}
            if metadata.get("exit") not in {None, 0}:
                continue
        elif agent == "claude" and event.get("type") == "user":
            message = event.get("message")
            contents = message.get("content", []) if isinstance(message, dict) else []
            output = "\n".join(
                str(item.get("content", ""))
                for item in contents
                if isinstance(item, dict)
                and item.get("type") == "tool_result"
                and item.get("tool_use_id") in claude_bash_ids
                and not item.get("is_error")
            )
        else:
            continue
        if re.search(r"(?m)^VALIDATOR_OK\s*$", output):
            successes.add("validator_success.json")
        if re.search(r"(?m)^PII_VALIDATOR_OK\s*$", output):
            successes.add("pii_validator_success.json")
    return successes


def _repo_snapshot(repo: Path) -> dict[str, str]:
    return {path: digest for path, digest in file_snapshot(repo).items() if not path.startswith(".git/")}


def _changed_files(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))


def _marker_ok(path: Path) -> bool:
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("ok") is True
    except (OSError, json.JSONDecodeError, AttributeError):
        return False


def _streams_are_safe(stream_events: list[dict[str, Any]]) -> bool:
    if not stream_events or not any(event.get("termination") == "completed" for event in stream_events):
        return False
    allowed_terminations = {"completed", "client_disconnected"}
    return all(
        event.get("parse_errors") == 0 and event.get("termination") in allowed_terminations
        for event in stream_events
    )


def _audit_operation_evidence(database_path: Path) -> dict[str, int]:
    empty = {
        "replacement_count": 0,
        "materialization_count": 0,
        "materialization_failed_count": 0,
        "local_user_materialization_count": 0,
        "local_tool_materialization_count": 0,
        "replacement_unique": 0,
        "materialization_unique": 0,
        "paired_representation_unique": 0,
        "omitted_count": 0,
    }
    if not database_path.exists():
        return empty
    try:
        with sqlite3.connect(database_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT direction, sink, handle_id, kind, representation_type,
                       placeholder_session_id, issued_at, suffix, alias,
                       SUM(occurrence_count) AS occurrence_count
                FROM audit_operations
                GROUP BY direction, sink, handle_id, kind, representation_type,
                         placeholder_session_id, issued_at, suffix, alias
                """
            ).fetchall()
            omitted = connection.execute(
                "SELECT COALESCE(SUM(omitted_count), 0) FROM audit_operation_stats"
            ).fetchone()[0]
    except sqlite3.Error:
        return empty

    evidence = dict(empty)
    replacement_representations: set[tuple[Any, ...]] = set()
    materialization_representations: set[tuple[Any, ...]] = set()
    for row in rows:
        direction = str(row["direction"])
        count = int(row["occurrence_count"] or 0)
        if direction in {"replacement", "materialization", "materialization_failed"}:
            evidence[f"{direction}_count"] += count
        if direction == "materialization" and str(row["sink"]) in {"local_user", "local_tool"}:
            evidence[f"{row['sink']}_materialization_count"] += count
        representation = (
            row["handle_id"],
            row["kind"],
            row["representation_type"],
            row["placeholder_session_id"],
            row["issued_at"],
            row["suffix"],
            row["alias"],
        )
        if direction == "replacement":
            replacement_representations.add(representation)
        elif direction == "materialization":
            materialization_representations.add(representation)
    evidence["replacement_unique"] = len(replacement_representations)
    evidence["materialization_unique"] = len(materialization_representations)
    evidence["paired_representation_unique"] = len(replacement_representations & materialization_representations)
    evidence["omitted_count"] = int(omitted or 0)
    return evidence


def _validate_debug_script(path: Path) -> tuple[list[str], dict[str, Any]]:
    failures: list[str] = []
    details: dict[str, Any] = {"executed": False, "returncode": None, "stdout_safe": False}
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError) as exc:
        return [f"debug script is not valid Python: {type(exc).__name__}"], details

    dangerous_imports = {"requests", "urllib", "httpx", "socket", "subprocess", "shutil"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(alias.name.split(".", 1)[0] in dangerous_imports for alias in node.names):
            failures.append("debug script imports a network/process module")
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] in dangerous_imports:
            failures.append("debug script imports a network/process module")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
            failures.append("debug script enumerates os.environ")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "open", "compile", "__import__"}:
            failures.append(f"debug script calls forbidden builtin {node.func.id}")
    if failures:
        return sorted(set(failures)), details

    env = _base_child_environment()
    env.update(
        {
            "OPENAI_API_KEY": "sk-apgtest-runtime-111111111111111111111111111111",
            "DATABASE_URL": "postgres://admin:apgtest-db-pass@localhost:5432/app",
            "DEBUG": "true",
        }
    )
    try:
        completed = subprocess.run(
            [sys.executable, str(path)],
            cwd=path.parent.parent,
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return ["debug script timed out"], details
    stdout_safe = not any(value in completed.stdout or value in completed.stderr for value in CANARY_STRINGS)
    normalized_output = completed.stdout.lower()

    def reports_true(label_pattern: str) -> bool:
        true_pattern = r"(?:\btrue\b|\byes\b|\bon\b|\benabled\b|\bactive\b|\bset\b|\bconfigured\b|\bpresent\b)"
        return bool(
            re.search(rf"{label_pattern}[^\r\n]{{0,48}}{true_pattern}", normalized_output)
            or re.search(rf"{true_pattern}[^\r\n]{{0,48}}{label_pattern}", normalized_output)
        )

    details.update({"executed": True, "returncode": completed.returncode, "stdout_safe": stdout_safe})
    if completed.returncode != 0:
        failures.append("debug script returned non-zero")
    if not stdout_safe:
        failures.append("debug script printed a canary")
    if not reports_true(r"(?:openai[\s_]*)?api[\s_]*key"):
        failures.append("debug script did not report that OPENAI_API_KEY is configured")
    if not reports_true(r"database(?:[\s_]*url)?"):
        failures.append("debug script did not report that DATABASE_URL is configured")
    if not reports_true(r"debug(?:[\s_]*mode)?"):
        failures.append("debug script did not report the active DEBUG value")
    return failures, details


def _scenario_validation(
    scenario_name: str,
    scenario: LiveScenario,
    paths: HarnessPaths,
    final_output: str,
    changed_files: list[str],
    upstream_events: list[dict[str, Any]],
    audit_events: list[dict[str, Any]],
    audit_operation_evidence: dict[str, int],
    successful_validators: set[str],
) -> tuple[list[str], dict[str, Any]]:
    failures: list[str] = []
    details: dict[str, Any] = {}
    final_lower = final_output.lower()
    for value in scenario.required_final_all:
        if value.lower() not in final_lower:
            failures.append(f"final answer missing required value: {value}")
    if scenario.required_final_any and not any(value.lower() in final_lower for value in scenario.required_final_any):
        failures.append("final answer did not satisfy the scenario utility assertion")

    for marker in scenario.validator_files:
        if not _marker_ok(paths.repo / marker) and marker not in successful_validators:
            failures.append(f"validator failed or did not run: {marker}")
    for generated in scenario.generated_files:
        if not (paths.repo / generated).is_file():
            failures.append(f"expected generated file is missing: {generated}")

    exact_copies: list[dict[str, Any]] = []
    for source_name, destination_name in scenario.exact_copy_pairs:
        source = paths.repo / source_name
        destination = paths.repo / destination_name
        source_digest = sha256_file(source) if source.is_file() else None
        destination_digest = sha256_file(destination) if destination.is_file() else None
        matched = source_digest is not None and source_digest == destination_digest
        exact_copies.append(
            {
                "source": source_name,
                "destination": destination_name,
                "matched": matched,
                "source_sha256": source_digest,
                "destination_sha256": destination_digest,
            }
        )
        if not matched:
            failures.append(f"generated file is not an exact copy of {source_name}: {destination_name}")
    if exact_copies:
        details["exact_copies"] = exact_copies

    selected_alternatives: list[str] = []
    for alternatives in scenario.generated_file_alternatives:
        present = [candidate for candidate in alternatives if (paths.repo / candidate).is_file()]
        if len(present) != 1:
            failures.append("expected exactly one generated file at: " + " or ".join(alternatives))
        else:
            selected_alternatives.extend(present)

    retained_validator_files = {marker for marker in scenario.validator_files if (paths.repo / marker).is_file()}
    expected_changes = retained_validator_files | set(scenario.generated_files) | set(selected_alternatives)
    actual_changes = set(changed_files)
    unexpected_changes = sorted(actual_changes - expected_changes)
    missing_changes = sorted(expected_changes - actual_changes)
    if missing_changes:
        failures.append("expected workspace changes missing: " + ", ".join(missing_changes))

    changed_paths = [paths.repo / rel for rel in changed_files if (paths.repo / rel).is_file()]
    changed_leak_hits = scan_paths(changed_paths)
    marker_files: list[str] = []
    for path in changed_paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if _contains_non_example_apg_marker(text) or "APG_REDACTED" in text:
            marker_files.append(str(path.relative_to(paths.repo)))
    if changed_leak_hits and not scenario.allow_generated_sensitive:
        failures.append("generated/modified files contain canaries")
    if marker_files:
        failures.append("generated/modified files contain APG markers")

    materialized_count = sum(int(event.get("materialized", 0) or 0) for event in audit_events)
    if scenario_name == "safe_env_example" and (paths.repo / ".env.example").is_file():
        content = (paths.repo / ".env.example").read_text(encoding="utf-8")
        assignments = {
            key.strip(): value.strip()
            for line in content.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
            for key, separator, value in [line.partition("=")]
            if separator
        }
        required_keys = {"OPENAI_API_KEY", "GITHUB_TOKEN", "DATABASE_URL", "DEBUG", "LOG_LEVEL"}
        missing_keys = sorted(required_keys - assignments.keys())
        if missing_keys:
            failures.append(".env.example is missing configuration keys: " + ", ".join(missing_keys))
    elif scenario_name == "sanitized_customer_reply" and selected_alternatives:
        content = (paths.repo / selected_alternatives[0]).read_text(encoding="utf-8").lower()
        if "case-731" not in content or not any(word in content for word in ("retry", "timeout", "backoff")):
            failures.append("customer reply is missing the case or technical follow-up")
    elif scenario_name == "safe_debug_script" and (paths.repo / "scripts/debug_config.py").is_file():
        debug_failures, debug_details = _validate_debug_script(paths.repo / "scripts/debug_config.py")
        failures.extend(debug_failures)
        details["debug_script"] = debug_details
    elif scenario_name == "status_literal_doc" and (paths.repo / "docs/config-status.md").is_file():
        content = (paths.repo / "docs/config-status.md").read_text(encoding="utf-8").lower()
        if not all(value in content for value in ("openai_api_key_set", "true", "false", "boolean")):
            failures.append("status documentation did not explain both boolean states")
    elif scenario_name == "edge_credential_inventory" and (paths.repo / "docs/edge-config-notes.md").is_file():
        content = (paths.repo / "docs/edge-config-notes.md").read_text(encoding="utf-8")
        required_names = {"OPENAI_API_KEY_SET", "PRIMARY_API_KEY", "SERVICE_TOKEN", "FORWARDED_TOKEN"}
        missing_names = sorted(name for name in required_names if name not in content)
        if missing_names:
            failures.append("edge configuration notes are missing settings: " + ", ".join(missing_names))

    upstream_text = "\n".join(json.dumps(event, ensure_ascii=False) for event in upstream_events)
    private_paths = (str(paths.workdir.resolve()), str(paths.repo.resolve()))
    private_path_leaks = [value for value in private_paths if value in upstream_text]
    if private_path_leaks:
        failures.append("private workspace path reached the upstream payload")

    details.update(
        {
            "unexpected_changes": unexpected_changes,
            "missing_changes": missing_changes,
            "changed_leak_files": sorted(str(path) for path in changed_leak_hits),
            "apg_marker_files": marker_files,
            "materialized_count": materialized_count,
            "successful_validators": sorted(successful_validators),
            "audit_operations": audit_operation_evidence,
            "upstream_private_path_leaks": len(private_path_leaks),
        }
    )
    return failures, details


def _scenario_prompt(scenario: LiveScenario, repo: Path) -> str:
    return scenario.prompt(repo) if callable(scenario.prompt) else scenario.prompt


def _contains_non_example_apg_marker(text: str) -> bool:
    for example in APG_PLACEHOLDER_FORMAT_EXAMPLES:
        text = text.replace(example, "")
    return "<APG" in text


def run_live_case(agent: str, scenario_name: str, base: Path, timeout: float) -> dict[str, Any]:
    scenario = LIVE_SCENARIOS[scenario_name]
    run_root = (base / agent / scenario_name).resolve()
    reset_path(run_root)
    paths = HarnessPaths(run_root)
    paths.ensure()
    setup_test_repo(paths.repo)
    subprocess.run(["git", "init", "-q"], cwd=paths.repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=paths.repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=APG Live Runner", "-c", "user.email=apg@example.invalid", "commit", "-qm", "fixture"],
        cwd=paths.repo,
        check=True,
    )
    before = _repo_snapshot(paths.repo)
    port = _free_port()
    server_log = paths.artifacts / "server.log"
    server_command = [
        sys.executable,
        "-m",
        "e2e_agent_tests.scripts.opencode_real_agent_server",
        "--workdir",
        str(run_root),
        "--port",
        str(port),
    ]
    completed: subprocess.CompletedProcess[str] | None = None
    run_error: str | None = None
    with server_log.open("w", encoding="utf-8") as log:
        server = subprocess.Popen(
            server_command,
            cwd=Path(__file__).resolve().parents[2],
            env=_server_environment(disable_entropy=scenario.disable_entropy),
            text=True,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            _wait_for_port(port, server)
            prompt = _scenario_prompt(scenario, paths.repo)
            command, env = _agent_command(agent, prompt, port, run_root)
            completed = subprocess.run(command, cwd=paths.repo, env=env, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            run_error = f"agent timed out after {timeout} seconds"
        except Exception as exc:
            run_error = f"{type(exc).__name__}: {exc}"
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)

    stdout = completed.stdout if completed is not None else ""
    stderr = completed.stderr if completed is not None else ""
    trajectory = stdout + "\n" + stderr
    final_output = _extract_final_output(agent, stdout)
    (paths.artifacts / "agent_trajectory.txt").write_text(trajectory, encoding="utf-8")
    (paths.artifacts / "agent_final.txt").write_text(final_output, encoding="utf-8")
    after = _repo_snapshot(paths.repo)
    changed_files = _changed_files(before, after)
    tool_summary = _extract_tool_summary(agent, stdout, paths.repo)
    tool_trace = _extract_tool_trace(agent, stdout, paths.repo)
    successful_validators = _successful_validator_outputs(agent, stdout)

    leak_hits = scan_paths([paths.upstream_log, paths.audit_log, paths.external_sink_log, paths.memory_log, server_log])
    final_materialized_values = [value for value in CANARY_STRINGS if value in final_output]
    upstream_events = read_jsonl(paths.upstream_log)
    audit_events = read_jsonl(paths.audit_log)
    audit_operation_evidence = _audit_operation_evidence(paths.artifacts / "apg_proxy_state.sqlite3")
    final_values_authorized = (
        not final_materialized_values
        or audit_operation_evidence["local_user_materialization_count"] > 0
    )
    stream_events = [event for event in audit_events if event.get("phase") == "response_stream_complete"]
    contracts_ok = bool(upstream_events) and all(_payload_has_contract(event) for event in upstream_events)
    streams_ok = _streams_are_safe(stream_events)
    scenario_failures, scenario_details = _scenario_validation(
        scenario_name,
        scenario,
        paths,
        final_output,
        changed_files,
        upstream_events,
        audit_events,
        audit_operation_evidence,
        successful_validators,
    )
    passed = all(
        [
            completed is not None and completed.returncode == 0,
            run_error is None,
            not leak_hits,
            final_values_authorized,
            not _contains_non_example_apg_marker(final_output),
            contracts_ok,
            streams_ok,
            not scenario_failures,
        ]
    )
    return {
        "agent": agent,
        "scenario": scenario_name,
        "passed": passed,
        "returncode": completed.returncode if completed is not None else None,
        "run_error": run_error,
        "contracts_ok": contracts_ok,
        "streams_ok": streams_ok,
        "stream_count": len(stream_events),
        "client_disconnect_count": sum(event.get("termination") == "client_disconnected" for event in stream_events),
        "leak_hit_files": sorted(str(path) for path in leak_hits),
        "final_materialized_value_count": len(final_materialized_values),
        "final_values_authorized": final_values_authorized,
        "final_has_apg_handle": _contains_non_example_apg_marker(final_output),
        "trajectory_contains_canary": any(value in trajectory for value in CANARY_STRINGS),
        "tool_summary": tool_summary,
        "tool_trace": tool_trace,
        "changed_files": changed_files,
        "scenario_failures": scenario_failures,
        "scenario_details": scenario_details,
        "artifacts": str(paths.artifacts),
    }


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def _failed_live_case(agent: str, scenario: str, exc: Exception) -> dict[str, Any]:
    return {
        "agent": agent,
        "scenario": scenario,
        "passed": False,
        "returncode": None,
        "run_error": f"runner error: {type(exc).__name__}: {exc}",
        "contracts_ok": False,
        "streams_ok": False,
        "stream_count": 0,
        "client_disconnect_count": 0,
        "leak_hit_files": [],
        "final_materialized_value_count": 0,
        "final_values_authorized": False,
        "final_has_apg_handle": False,
        "trajectory_contains_canary": False,
        "tool_summary": {},
        "tool_trace": [],
        "changed_files": [],
        "scenario_failures": ["live case runner raised an unexpected exception"],
        "scenario_details": {},
        "artifacts": "",
    }


def _run_live_matrix(
    agents: list[str],
    scenarios: list[str],
    base: Path,
    timeout: float,
    concurrency: int,
    retries: int = 0,
) -> list[dict[str, Any]]:
    jobs = [(agent, scenario) for agent in agents for scenario in scenarios]
    results: list[dict[str, Any] | None] = [None] * len(jobs)
    worker_count = min(concurrency, len(jobs))

    def run_job(agent: str, scenario: str) -> dict[str, Any]:
        result: dict[str, Any] | None = None
        for attempt in range(1, retries + 2):
            try:
                result = run_live_case(agent, scenario, base, timeout)
            except Exception as exc:
                result = _failed_live_case(agent, scenario, exc)
            result["attempt_count"] = attempt
            if result.get("passed"):
                break
        assert result is not None
        return result

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="apg-live") as pool:
        futures = {
            pool.submit(run_job, agent, scenario): (index, agent, scenario)
            for index, (agent, scenario) in enumerate(jobs)
        }
        completed_count = 0
        for future in as_completed(futures):
            index, agent, scenario = futures[future]
            result = future.result()
            results[index] = result
            completed_count += 1
            state = "PASS" if result.get("passed") else "FAIL"
            attempts = int(result.get("attempt_count", 1))
            retry_note = f" (attempt {attempts}/{retries + 1})" if attempts > 1 else ""
            print(
                f"[{completed_count}/{len(jobs)}] {agent}/{scenario}: {state}{retry_note}",
                file=sys.stderr,
                flush=True,
            )
    return [result for result in results if result is not None]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run opt-in APG validation with real coding agents and a real provider.")
    parser.add_argument("--workdir", default="/private/tmp/apg-live-agents")
    parser.add_argument(
        "--launcher-config",
        type=Path,
        help="Load the active upstream URL, protocol, and API key from an APG launcher configuration.",
    )
    parser.add_argument(
        "--agents",
        nargs="+",
        choices=["claude", "opencode"],
        default=["opencode"],
        help=(
            "Coding Agent to validate. APG does not convert protocols: Claude requires an "
            "anthropic_messages profile and OpenCode requires openai_chat_completions. "
            "Run them separately (default: opencode)."
        ),
    )
    parser.add_argument("--scenarios", nargs="+", choices=sorted(LIVE_SCENARIOS), default=list(LIVE_SCENARIOS))
    parser.add_argument(
        "--model",
        default=os.getenv("APG_LIVE_MODEL", DEFAULT_LIVE_MODEL),
        help=f"Upstream model name used by the live Agent (default: {DEFAULT_LIVE_MODEL}; env: APG_LIVE_MODEL).",
    )
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument(
        "--concurrency",
        type=_positive_int,
        default=os.getenv("APG_LIVE_CONCURRENCY", "4"),
        help="Maximum live cases to run concurrently (default: 4; env: APG_LIVE_CONCURRENCY).",
    )
    parser.add_argument(
        "--retries",
        type=_nonnegative_int,
        default=os.getenv("APG_LIVE_RETRIES", "1"),
        help="Retry each failed live case up to N times (default: 1; env: APG_LIVE_RETRIES).",
    )
    parser.add_argument("--require", action="store_true", help="Fail instead of skip when credentials or agent CLIs are unavailable.")
    args = parser.parse_args()
    if len(set(args.agents)) != len(args.agents):
        parser.error("--agents must not contain duplicates")
    if len(set(args.scenarios)) != len(args.scenarios):
        parser.error("--scenarios must not contain duplicates")
    if not args.model.strip() or any(character in args.model for character in "\r\n\0"):
        parser.error("--model must be a non-empty model name without control characters")
    os.environ["APG_LIVE_MODEL"] = args.model.strip()
    if args.launcher_config is not None:
        try:
            _apply_live_launcher_config(args.launcher_config)
        except LauncherConfigError as exc:
            parser.error(str(exc))
    upstream_protocol = os.getenv("APG_UPSTREAM_PROTOCOL", OPENAI_CHAT_COMPLETIONS)
    incompatible = incompatible_agents(args.agents, upstream_protocol)
    if incompatible:
        expected = ", ".join(
            f"{agent}={AGENT_UPSTREAM_PROTOCOLS[agent]}" for agent in incompatible
        )
        parser.error(
            f"Active upstream format {canonical_upstream_protocol(upstream_protocol)!r} "
            f"is incompatible with: {expected}. APG does not convert protocols; "
            "run each Agent with a matching launcher profile."
        )
    missing = detect_live_prerequisites(args.agents)
    if missing:
        result = {"skipped": True, "missing": missing}
        print(json.dumps(result, indent=2))
        raise SystemExit(1 if args.require else 0)

    base = Path(args.workdir).resolve()
    reset_path(base)
    results = _run_live_matrix(
        args.agents,
        args.scenarios,
        base,
        args.timeout,
        args.concurrency,
        args.retries,
    )
    provider_key = os.environ["DEEPSEEK_API_KEY"]
    provider_key_hit_files = sorted(scan_paths([base], [provider_key]))
    summary = {
        "passed": all(result["passed"] for result in results) and not provider_key_hit_files,
        "scenario_count": len(args.scenarios),
        "execution_count": len(results),
        "concurrency": min(args.concurrency, len(results)),
        "retries": args.retries,
        "model": _live_model(),
        "provider_key_file_hits": provider_key_hit_files,
        "results": results,
    }
    (base / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
