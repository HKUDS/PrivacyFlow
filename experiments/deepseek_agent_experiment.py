#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

import httpx

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import create_app


class FakeUpstream:
    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []

    async def request_json(self, method: str, path: str, payload: Any | None = None) -> tuple[int, dict[str, str], Any]:
        self.payloads.append({"method": method, "path": path, "payload": payload})
        return (
            200,
            {"content-type": "application/json"},
            {
                "id": "dry-run",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Dry-run agent plan received. Echo test sk-proj-abcdefghijklmnopqrstuvwxyz123456 should be redacted.",
                        },
                        "finish_reason": "stop",
                    }
                ],
            },
        )


def build_messages(task: str) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": (
                "You are a concise coding-agent experiment runner. Inspect the sanitized project context, "
                "propose concrete next steps, and never ask for raw secrets."
            ),
        },
        {
            "role": "user",
            "content": (
                f"{task}\n\n"
                "Privacy-gateway stress sample: email howard@example.com, "
                "path /Users/howard/private/project/.env, "
                "fake key sk-proj-abcdefghijklmnopqrstuvwxyz123456."
            ),
        },
    ]


async def run_experiment(args: argparse.Namespace) -> int:
    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if args.live and not api_key:
        print("DEEPSEEK_API_KEY is required for --live. No key was read from files or arguments.")
        return 2

    with tempfile.TemporaryDirectory(prefix="apg-deepseek-exp-") as tmp:
        tmp_path = Path(tmp)
        cfg = GatewayConfig(
            database_path=str(tmp_path / "state.sqlite3"),
            audit_log_path=str(tmp_path / "audit.jsonl"),
            signing_secret=os.getenv("APG_SIGNING_SECRET", f"exp-{uuid.uuid4().hex}"),
            local_api_keys={"apg-local"},
            workspace_id="experiment",
            upstream=UpstreamConfig(
                base_url=args.base_url,
                api_key=api_key if args.live else "dry-run-key",
                timeout_seconds=args.timeout,
                strip_local_v1=args.strip_local_v1,
            ),
        )
        fake = None if args.live else FakeUpstream()
        app = create_app(cfg, fake)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://apg.local") as client:
            response = await client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer apg-local", "X-APG-Session-ID": "sess_experiment"},
                json={
                    "model": args.model,
                    "messages": build_messages(args.task),
                    "stream": False,
                    "temperature": args.temperature,
                    "max_tokens": args.max_tokens,
                },
                timeout=args.timeout,
            )

        audit_events = []
        audit_path = tmp_path / "audit.jsonl"
        if audit_path.exists():
            audit_events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        request_detections = sum(len(e.get("detections", [])) for e in audit_events if e.get("phase") == "request")
        response_detections = sum(len(e.get("detections", [])) for e in audit_events if e.get("phase") == "response")

        result = {
            "mode": "live" if args.live else "dry-run",
            "status_code": response.status_code,
            "model": args.model,
            "request_redactions": request_detections,
            "response_redactions": response_detections,
            "upstream_path": fake.payloads[0]["path"] if fake and fake.payloads else "live-network",
            "contains_raw_stress_secret_in_returned_body": "sk-proj-" in response.text,
            "assistant_excerpt": _assistant_excerpt(response),
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if response.status_code < 500 and not result["contains_raw_stress_secret_in_returned_body"] else 1


def _assistant_excerpt(response: httpx.Response) -> str:
    try:
        data = response.json()
        content = data["choices"][0]["message"]["content"]
    except Exception:
        content = response.text
    return content[:500]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a safe APG + DeepSeek coding-agent experiment.")
    parser.add_argument("--live", action="store_true", help="Call the real DeepSeek API. Requires DEEPSEEK_API_KEY.")
    parser.add_argument("--model", default="deepseek-v4-flash", help="DeepSeek model to use.")
    parser.add_argument("--base-url", default="https://api.deepseek.com", help="DeepSeek OpenAI-compatible base URL.")
    parser.add_argument("--strip-local-v1", action=argparse.BooleanOptionalAction, default=True, help="Map local /v1 paths to upstream paths without /v1.")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--max-tokens", type=int, default=500)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument(
        "--task",
        default="Review this Agent Privacy Gateway MVP at a high level and suggest the next three highest-impact experiments.",
    )
    return parser.parse_args()


def main() -> None:
    raise SystemExit(asyncio.run(run_experiment(parse_args())))


if __name__ == "__main__":
    main()
