from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

import httpx

from e2e_agent_tests.scripts.check_leaks import scan_paths
from e2e_agent_tests.scripts.common import HarnessPaths, read_jsonl, reset_path
from e2e_agent_tests.scripts.real_api_gateway import RecordingUpstreamClient
from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import create_app


CANARY = "sk-apgtest-responses-live-abcdefghijklmnopqrstuvwxyz"


async def run_live(workdir: Path, model: str, timeout: float) -> dict:
    key = os.getenv("OPENAI_API_KEY", "")
    if not key:
        return {"skipped": True, "missing": ["OPENAI_API_KEY"]}
    reset_path(workdir)
    paths = HarnessPaths(workdir)
    paths.ensure()
    upstream_config = UpstreamConfig(base_url="https://api.openai.com", api_key=key, timeout_seconds=timeout)
    config = GatewayConfig(
        database_path=str(paths.artifacts / "state.sqlite3"),
        audit_log_path=str(paths.audit_log),
        signing_secret="openai-responses-live-secret",
        local_api_keys={"apg-local"},
        workspace_id="openai-responses-live",
        upstream=upstream_config,
    )
    app = create_app(config, RecordingUpstreamClient(upstream_config, paths.upstream_log))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://apg.local", timeout=timeout + 10) as client:
        async with client.stream(
            "POST",
            "/v1/responses",
            headers={"Authorization": "Bearer apg-local"},
            json={
                "model": model,
                "stream": True,
                "input": f"A protected test value is {CANARY}. Do not repeat it. Reply exactly APG_RESPONSES_OK.",
            },
        ) as response:
            body = (await response.aread()).decode("utf-8", errors="replace")
            status_code = response.status_code
    (paths.artifacts / "response.sse").write_text(body, encoding="utf-8")
    leaks = scan_paths([paths.upstream_log, paths.audit_log])
    stream_events = [event for event in read_jsonl(paths.audit_log) if event.get("phase") == "response_stream_complete"]
    passed = all(
        [
            status_code == 200,
            not leaks,
            CANARY not in body,
            "<APG" not in body,
            "APG_RESPONSES_OK" in body,
            bool(stream_events),
            all(event.get("parse_errors") == 0 and event.get("termination") == "completed" for event in stream_events),
        ]
    )
    return {"skipped": False, "passed": passed, "status_code": status_code, "leak_hits": leaks, "artifacts": str(paths.artifacts)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an opt-in real OpenAI Responses streaming validation through APG.")
    parser.add_argument("--workdir", default=".apg-openai-responses-live")
    parser.add_argument("--model", default=os.getenv("OPENAI_RESPONSES_MODEL", "gpt-4.1-mini"))
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--require", action="store_true")
    args = parser.parse_args()
    result = asyncio.run(run_live(Path(args.workdir), args.model, args.timeout))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("skipped"):
        raise SystemExit(1 if args.require else 0)
    raise SystemExit(0 if result.get("passed") else 1)


if __name__ == "__main__":
    main()
