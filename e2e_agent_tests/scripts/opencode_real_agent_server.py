from __future__ import annotations

import argparse
import os
import uuid
from pathlib import Path

import uvicorn

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.detectors.rules import builtin_rules
from gateway.server import create_app
from gateway.upstream_protocol import (
    ANTHROPIC_MESSAGES,
    LEGACY_UPSTREAM_PROTOCOLS,
    OPENAI_CHAT_COMPLETIONS,
    SUPPORTED_UPSTREAM_PROTOCOLS,
    canonical_upstream_protocol,
)

from e2e_agent_tests.scripts.common import HarnessPaths
from e2e_agent_tests.scripts.real_api_gateway import RecordingUpstreamClient


def build_app(
    workdir: Path,
    upstream_protocol: str,
    upstream_base_url: str,
    upstream_api_key: str,
    model_timeout: float,
):
    paths = HarnessPaths(workdir)
    paths.ensure()
    upstream_protocol = canonical_upstream_protocol(upstream_protocol)
    config = GatewayConfig(
        database_path=str(paths.artifacts / "apg_proxy_state.sqlite3"),
        audit_log_path=str(paths.audit_log),
        signing_secret=f"opencode-real-agent-{uuid.uuid4().hex}",
        local_api_keys={"apg-local"},
        workspace_id="opencode-real-agent",
        detectors_config=_detectors_config(),
        upstream=UpstreamConfig(
            protocol=upstream_protocol,
            base_url=upstream_base_url,
            api_key=upstream_api_key,
            timeout_seconds=model_timeout,
            strip_local_v1=upstream_protocol != ANTHROPIC_MESSAGES,
        ),
    )
    upstream = RecordingUpstreamClient(config.upstream, paths.upstream_log)
    return create_app(config, upstream)


def _detectors_config() -> dict:
    if os.getenv("APG_LIVE_DISABLE_ENTROPY") != "1":
        return {}
    return {
        "flow": {
            "id": "live_no_entropy",
            "modules": [
                {
                    "id": "builtin_rules",
                    "type": "regex_rules",
                    "rules": [rule.__dict__ for rule in builtin_rules()],
                    "fail_open": False,
                    "stream_safe": True,
                },
                {
                    "id": "paths",
                    "type": "path_detector",
                    "fail_open": False,
                    "stream_safe": True,
                },
            ],
        }
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an APG proxy for real OpenCode E2E tests.")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--upstream-protocol",
        choices=sorted({*SUPPORTED_UPSTREAM_PROTOCOLS, *LEGACY_UPSTREAM_PROTOCOLS}),
        default=os.getenv("APG_UPSTREAM_PROTOCOL", OPENAI_CHAT_COMPLETIONS),
    )
    parser.add_argument("--upstream-base-url", default=os.getenv("APG_UPSTREAM_BASE_URL", "https://api.deepseek.com"))
    parser.add_argument("--upstream-api-key-env", default="DEEPSEEK_API_KEY")
    args = parser.parse_args()

    key = os.getenv(args.upstream_api_key_env, "")
    if not key:
        raise SystemExit(f"{args.upstream_api_key_env} is required")

    app = build_app(Path(args.workdir), args.upstream_protocol, args.upstream_base_url, key, args.timeout)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
