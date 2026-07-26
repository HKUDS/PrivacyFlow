from __future__ import annotations

import argparse
import json
import re
import sqlite3
from datetime import date
from pathlib import Path
from typing import Any

from e2e_agent_tests.scripts.setup_test_repo import FILES


SCENARIO_FILES: dict[str, list[str]] = {
    "secret_tool": [".env", "scripts/validate_secret.py"],
    "pii_tool": ["docs/customer_notes.md", "scripts/validate_pii.py"],
    "parallel_materialization": [".env", "docs/customer_notes.md", "scripts/validate_secret.py", "scripts/validate_pii.py"],
    "config_debug": [".env", "src/client.py", "src/config.py"],
    "pii_summary": ["docs/customer_notes.md"],
    "log_analysis": ["logs/error.log", "src/client.py"],
    "path_alias": ["private/path_probe.txt"],
    "multi_file_review": ["src/config.py", "src/client.py", ".env", "logs/error.log", "docs/customer_notes.md"],
    "safe_env_example": [".env", "src/config.py"],
    "exact_sensitive_copy": ["fixtures/sensitive_commands.txt"],
    "sanitized_customer_reply": ["docs/customer_notes.md"],
    "safe_debug_script": ["src/config.py"],
    "status_literal_doc": [],
    "edge_credential_inventory": ["config/edge.env"],
    "inline_assignment_log": ["logs/assignment_edge.log"],
}

APG_PLACEHOLDER_RE = re.compile(
    r"<APG:v1:[^:>]+:(?P<handle>[^:>]+):[^:>]+:(?P<issued_at>\d+):[^>]+>"
)


def _display_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, indent=2)


def _claude_transcript(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    tool_names: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            items.append({"kind": "error", "title": "Unparsed output", "text": line})
            continue
        event_type = event.get("type")
        if event_type == "system" and event.get("subtype") == "init":
            items.append(
                {
                    "kind": "session",
                    "title": "Claude Code session",
                    "timestamp": event.get("timestamp"),
                    "data": {
                        "version": event.get("claude_code_version"),
                        "model": event.get("model"),
                        "cwd": event.get("cwd"),
                        "permission_mode": event.get("permissionMode"),
                        "tools_reported_by_agent": event.get("tools", []),
                        "agents": event.get("agents", []),
                    },
                }
            )
        elif event_type == "assistant":
            message = event.get("message") if isinstance(event.get("message"), dict) else {}
            for block in message.get("content", []):
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    items.append(
                        {
                            "kind": "assistant",
                            "title": "Claude",
                            "timestamp": event.get("timestamp"),
                            "text": str(block.get("text", "")),
                        }
                    )
                elif block.get("type") == "tool_use":
                    call_id = str(block.get("id", ""))
                    tool_name = str(block.get("name", "Tool"))
                    tool_names[call_id] = tool_name
                    items.append(
                        {
                            "kind": "tool_call",
                            "title": tool_name,
                            "timestamp": event.get("timestamp"),
                            "call_id": call_id,
                            "input": _display_value(block.get("input", {})),
                        }
                    )
        elif event_type == "user":
            message = event.get("message") if isinstance(event.get("message"), dict) else {}
            for block in message.get("content", []):
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                call_id = str(block.get("tool_use_id", ""))
                items.append(
                    {
                        "kind": "tool_result",
                        "title": tool_names.get(call_id, "Tool result"),
                        "timestamp": event.get("timestamp"),
                        "call_id": call_id,
                        "is_error": bool(block.get("is_error")),
                        "output": _display_value(block.get("content", "")),
                    }
                )
        elif event_type == "result":
            usage = event.get("usage") if isinstance(event.get("usage"), dict) else {}
            items.append(
                {
                    "kind": "run_summary",
                    "title": "Claude Code run complete",
                    "data": {
                        "terminal_reason": event.get("terminal_reason"),
                        "stop_reason": event.get("stop_reason"),
                        "turns": event.get("num_turns"),
                        "duration_ms": event.get("duration_ms"),
                        "output_tokens": usage.get("output_tokens"),
                        "cost_usd": event.get("total_cost_usd"),
                    },
                }
            )
    return items


def _opencode_transcript(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            items.append({"kind": "error", "title": "Unparsed output", "text": line})
            continue
        event_type = event.get("type")
        part = event.get("part") if isinstance(event.get("part"), dict) else {}
        if event_type == "tool_use":
            state = part.get("state") if isinstance(part.get("state"), dict) else {}
            items.append(
                {
                    "kind": "tool",
                    "title": str(part.get("tool", "Tool")),
                    "timestamp": event.get("timestamp"),
                    "call_id": str(part.get("callID", "")),
                    "status": state.get("status"),
                    "input": _display_value(state.get("input", {})),
                    "output": _display_value(state.get("output", "")),
                }
            )
        elif event_type == "text":
            items.append(
                {
                    "kind": "assistant",
                    "title": "OpenCode",
                    "timestamp": event.get("timestamp"),
                    "text": str(part.get("text", "")),
                }
            )
        elif event_type == "step_finish":
            tokens = part.get("tokens") if isinstance(part.get("tokens"), dict) else {}
            cache = tokens.get("cache") if isinstance(tokens.get("cache"), dict) else {}
            items.append(
                {
                    "kind": "step_summary",
                    "title": "Step complete",
                    "timestamp": event.get("timestamp"),
                    "data": {
                        "reason": part.get("reason"),
                        "input_tokens": tokens.get("input"),
                        "output_tokens": tokens.get("output"),
                        "reasoning_tokens": tokens.get("reasoning"),
                        "cache_read_tokens": cache.get("read"),
                    },
                }
            )
    return items


def _transcript(artifacts: str, agent: str) -> dict[str, Any]:
    path = Path(artifacts) / "agent_trajectory.txt"
    if not path.is_file():
        return {"source": str(path), "line_count": 0, "items": []}
    items = _claude_transcript(path) if agent == "claude" else _opencode_transcript(path)
    return {
        "source": str(path),
        "line_count": len(path.read_text(encoding="utf-8", errors="replace").splitlines()),
        "items": items,
    }


def _operation_annotations(artifacts: str) -> list[dict[str, Any]]:
    artifact_path = Path(artifacts)
    database = artifact_path / "apg_proxy_state.sqlite3"
    if not database.is_file():
        return []

    upstream_text = ""
    upstream_log = artifact_path / "upstream_requests.jsonl"
    if upstream_log.is_file():
        upstream_text = upstream_log.read_text(encoding="utf-8", errors="replace")
    placeholders: dict[tuple[str, int], str] = {}
    placeholders_by_handle: dict[str, str] = {}
    for match in APG_PLACEHOLDER_RE.finditer(upstream_text):
        placeholder = match.group(0)
        handle = match.group("handle")
        issued_at = int(match.group("issued_at"))
        placeholders[(handle, issued_at)] = placeholder
        placeholders_by_handle.setdefault(handle, placeholder)

    try:
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT o.request_id, o.timestamp, o.direction, o.handle_id, o.kind, o.subtype,
                   o.detector, o.action, o.sink, o.result_code,
                   o.representation_type, o.issued_at, o.suffix, o.alias,
                   o.tool_name, o.occurrence_count, m.value
            FROM audit_operations AS o
            LEFT JOIN mappings AS m ON m.handle_id = o.handle_id
            WHERE o.direction IN ('replacement', 'materialization')
              AND o.result_code = 'OK'
            ORDER BY o.id
            """
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        if "connection" in locals():
            connection.close()

    grouped: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        original = row["value"]
        if not isinstance(original, str) or not original:
            continue
        if row["representation_type"] == "path_alias":
            representation = str(row["alias"] or "")
        else:
            representation = placeholders.get(
                (str(row["handle_id"]), int(row["issued_at"] or 0)),
                placeholders_by_handle.get(str(row["handle_id"]), "APG signed placeholder"),
            ) + str(row["suffix"] or "")
        key = (
            str(row["direction"]),
            original,
            representation,
            str(row["kind"]),
            str(row["subtype"]),
            str(row["tool_name"] or ""),
        )
        annotation = grouped.setdefault(
            key,
            {
                "direction": str(row["direction"]),
                "original": original,
                "representation": representation,
                "kind": str(row["kind"]),
                "subtype": str(row["subtype"]),
                "detector": str(row["detector"] or ""),
                "action": str(row["action"] or ""),
                "sink": str(row["sink"] or ""),
                "result_code": str(row["result_code"] or ""),
                "tool_name": str(row["tool_name"] or ""),
                "occurrence_count": 0,
                "request_ids": [],
                "timestamps": [],
            },
        )
        annotation["occurrence_count"] += int(row["occurrence_count"] or 0)
        request_id = str(row["request_id"] or "")
        if request_id and request_id not in annotation["request_ids"]:
            annotation["request_ids"].append(request_id)
        timestamp = int(row["timestamp"] or 0)
        if timestamp and timestamp not in annotation["timestamps"]:
            annotation["timestamps"].append(timestamp)
    return sorted(
        grouped.values(),
        key=lambda item: (
            item["direction"],
            item["tool_name"],
            item["kind"],
            item["subtype"],
            item["original"],
        ),
    )


def _safe_result(result: dict[str, Any]) -> dict[str, Any]:
    details = result.get("scenario_details") if isinstance(result.get("scenario_details"), dict) else {}
    audit = details.get("audit_operations") if isinstance(details.get("audit_operations"), dict) else {}
    return {
        "passed": bool(result.get("passed")),
        "stream_count": int(result.get("stream_count", 0) or 0),
        "client_disconnect_count": int(result.get("client_disconnect_count", 0) or 0),
        "changed_files": [str(value) for value in result.get("changed_files", [])],
        "tool_summary": result.get("tool_summary", {}),
        "tool_trace": result.get("tool_trace", []),
        "materialized_count": int(details.get("materialized_count", 0) or 0),
        "failed_materializations": int(audit.get("materialization_failed_count", 0) or 0),
        "leak_file_count": len(result.get("leak_hit_files", [])),
        "final_leak_count": int(result.get("final_leak_count", 0) or 0),
        "final_has_apg_handle": bool(result.get("final_has_apg_handle")),
        "scenario_failures": [str(value) for value in result.get("scenario_failures", [])],
        "artifacts": str(result.get("artifacts", "")),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export sanitized real-agent evidence for the scenario HTML.")
    parser.add_argument("--summary", action="append", required=True, help="Summary JSON; later files override the same agent/scenario.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--generated-at", default=date.today().isoformat())
    args = parser.parse_args()

    results: dict[str, dict[str, Any]] = {}
    provider_key_hits = 0
    for summary_name in args.summary:
        summary = json.loads(Path(summary_name).read_text(encoding="utf-8"))
        provider_key_hits += len(summary.get("provider_key_file_hits", []))
        for result in summary.get("results", []):
            agent = str(result.get("agent", ""))
            scenario = str(result.get("scenario", ""))
            if agent and scenario:
                safe_result = _safe_result(result)
                safe_result["transcript"] = _transcript(safe_result["artifacts"], agent)
                safe_result["operations"] = _operation_annotations(safe_result["artifacts"])
                results.setdefault(scenario, {})[agent] = safe_result

    agent_reported_tools: dict[str, list[str]] = {"claude": [], "opencode": []}
    for scenario_results in results.values():
        for agent, result in scenario_results.items():
            for item in result.get("transcript", {}).get("items", []):
                if item.get("kind") not in {"tool", "tool_call"}:
                    continue
                tool_name = str(item.get("title", ""))
                if tool_name and tool_name not in agent_reported_tools.setdefault(agent, []):
                    agent_reported_tools[agent].append(tool_name)

    payload = {
        "generated_at": args.generated_at,
        "configured_tools": ["Read", "Glob", "Grep", "Edit", "Write", "Bash"],
        "agent_reported_tools": agent_reported_tools,
        "uniform_denials": ["direct WebFetch", "external directories", "ordinary outbound network through environment proxy"],
        "provider_key_file_hits": provider_key_hits,
        "repository_files": sorted(FILES),
        "scenario_files": SCENARIO_FILES,
        "fixtures": {name: FILES[name] for name in sorted(FILES)},
        "results": results,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "window.APG_LIVE_EVIDENCE = " + json.dumps(payload, ensure_ascii=False, indent=2) + ";\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
