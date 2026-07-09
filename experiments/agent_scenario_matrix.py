#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Scenario:
    name: str
    command: list[str]
    proves: str


SCENARIOS = [
    Scenario(
        "recursive_request_redaction",
        [".venv/bin/python", "-m", "pytest", "tests/test_redaction.py", "tests/test_detectors.py"],
        "Requests are recursively scanned, common secret/PII/path detectors fire, and normal API routes are not misclassified.",
    ),
    Scenario(
        "signed_placeholder_materialization",
        [".venv/bin/python", "-m", "pytest", "tests/test_placeholder_parser.py", "tests/test_mapping_lifecycle.py"],
        "Valid placeholders are session/workspace scoped; spoofed, expired, tombstoned, and traversal cases fail closed.",
    ),
    Scenario(
        "proxy_and_deepseek_pathing",
        [".venv/bin/python", "-m", "pytest", "tests/test_proxy_openai_chat.py", "tests/test_deepseek_config.py"],
        "The OpenAI-compatible proxy forwards sanitized requests, scans responses, audits requests, and can map APG /v1 paths to DeepSeek upstream paths.",
    ),
    Scenario(
        "tool_call_arg_materialization",
        [".venv/bin/python", "-m", "pytest", "tests/test_response_tool_args_materialization.py"],
        "Secrets in tool_call arguments are restored for the harness; visible text and forged placeholders are handled safely.",
    ),
    Scenario(
        "stream_response_scan",
        [".venv/bin/python", "-m", "pytest", "tests/test_stream_response_scan.py"],
        "Streamed response deltas are scanned for echoed secrets.",
    ),
    Scenario(
        "upstream_error_normalization",
        [".venv/bin/python", "-m", "pytest", "tests/test_upstream_errors.py"],
        "Upstream httpx failures return 502/504 without leaking tracebacks.",
    ),
    Scenario(
        "strict_and_pii_mode",
        [".venv/bin/python", "-m", "pytest", "tests/test_strict_pii_mode.py"],
        "strict_mode guards default key/secret; pii_mode pseudonymize/redact/allow switch the PII disposition.",
    ),
    Scenario(
        "deepseek_harness_dry_run",
        [".venv/bin/python", "experiments/deepseek_agent_experiment.py"],
        "The DeepSeek experiment harness runs through APG without a real key and redacts both request-side and response-side stress secrets.",
    ),
]


def run_local() -> int:
    results = []
    for scenario in SCENARIOS:
        proc = subprocess.run(scenario.command, cwd=Path(__file__).resolve().parents[1], text=True, capture_output=True, timeout=120)
        results.append(
            {
                "name": scenario.name,
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "proves": scenario.proves,
                "stdout_tail": proc.stdout[-1200:],
                "stderr_tail": proc.stderr[-1200:],
            }
        )
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0 if all(r["ok"] for r in results) else 1


def run_opencode(args: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parents[1]
    tmp_manager = None
    if args.xdg_root:
        tmp_path = Path(args.xdg_root)
        tmp_path.mkdir(parents=True, exist_ok=True)
    else:
        tmp_manager = tempfile.TemporaryDirectory(prefix="opencode-apg-matrix-")
        tmp_path = Path(tmp_manager.name)
    try:
        env = os.environ.copy()
        env["XDG_DATA_HOME"] = str(tmp_path / "data")
        env["XDG_CONFIG_HOME"] = str(tmp_path / "config")
        prompt = (
            "You are validating Agent Privacy Gateway as a real coding agent. "
            "Do not edit files. Run or inspect the following scenario commands and report pass/fail with concise evidence:\n\n"
            + "\n".join(f"- {s.name}: {' '.join(s.command)} | proves: {s.proves}" for s in SCENARIOS)
        )
        cmd = [
            "opencode",
            "run",
            "--model",
            args.model,
            "--format",
            "json" if args.json else "default",
            prompt,
        ]
        try:
            proc = subprocess.run(cmd, cwd=root, text=True, capture_output=True, timeout=args.timeout, env=env)
        except subprocess.TimeoutExpired as exc:
            print(
                json.dumps(
                    {
                        "agent": "opencode",
                        "ok": False,
                        "error": "APG_REAL_AGENT_TIMEOUT",
                        "timeout_seconds": args.timeout,
                        "stdout_tail": (exc.stdout or "")[-1200:] if isinstance(exc.stdout, str) else "",
                        "stderr_tail": (exc.stderr or "")[-1200:] if isinstance(exc.stderr, str) else "",
                        "next_action": "configure a stable provider/key, then rerun the same matrix",
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 124
        print(proc.stdout)
        if proc.stderr.strip():
            print(proc.stderr)
        return proc.returncode
    finally:
        if tmp_manager is not None:
            tmp_manager.cleanup()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run APG scenario validation locally or through a real OpenCode agent.")
    parser.add_argument("--agent", choices=["local", "opencode"], default="local")
    parser.add_argument("--model", default="opencode/deepseek-v4-flash-free")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--xdg-root", help="Directory for temporary OpenCode config/data during real-agent validation.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.agent == "opencode":
        raise SystemExit(run_opencode(args))
    raise SystemExit(run_local())


if __name__ == "__main__":
    main()
