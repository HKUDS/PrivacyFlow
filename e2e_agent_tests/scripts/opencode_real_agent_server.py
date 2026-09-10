from __future__ import annotations

import argparse
import os
import uuid
from pathlib import Path

import uvicorn

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import create_app
from gateway.upstream_protocol import (
    ANTHROPIC_MESSAGES,
    OPENAI_CHAT_COMPLETIONS,
    SUPPORTED_UPSTREAM_PROTOCOLS,
    canonical_upstream_protocol,
)

from e2e_agent_tests.scripts.common import HarnessPaths
from e2e_agent_tests.scripts.real_api_gateway import RecordingUpstreamClient

DEEPSEEK_OPENAI_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"


def live_upstream_base_url(protocol: str, configured: str = "") -> str:
    """Choose DeepSeek's documented root for the active native protocol.

    Anthropic clients must use ``https://api.deepseek.com/anthropic``, not the
    OpenAI-compatible host root. See https://api-docs.deepseek.com/guides/anthropic_api
    """
    protocol = canonical_upstream_protocol(protocol)
    raw = configured.strip().rstrip("/")
    if protocol == ANTHROPIC_MESSAGES:
        if raw in {"", DEEPSEEK_OPENAI_BASE_URL, f"{DEEPSEEK_OPENAI_BASE_URL}/v1"}:
            return DEEPSEEK_ANTHROPIC_BASE_URL
        return raw
    return raw or DEEPSEEK_OPENAI_BASE_URL


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
    upstream_base_url = live_upstream_base_url(upstream_protocol, upstream_base_url)
    config = GatewayConfig(
        database_path=str(paths.artifacts / "pf_proxy_state.sqlite3"),
        audit_log_path=str(paths.audit_log),
        signing_secret=f"opencode-real-agent-{uuid.uuid4().hex}",
        local_api_keys={"pf-local"},
        workspace_id="opencode-real-agent",
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
def main() -> None:
    parser = argparse.ArgumentParser(description="Run a PF proxy for real OpenCode E2E tests.")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--upstream-protocol",
        choices=sorted(SUPPORTED_UPSTREAM_PROTOCOLS),
        default=os.getenv("PF_UPSTREAM_PROTOCOL", OPENAI_CHAT_COMPLETIONS),
    )
    parser.add_argument("--upstream-base-url", default=os.getenv("PF_UPSTREAM_BASE_URL", ""))
    parser.add_argument("--upstream-api-key-env", default="DEEPSEEK_API_KEY")
    args = parser.parse_args()

    key = os.getenv(args.upstream_api_key_env, "")
    if not key:
        raise SystemExit(f"{args.upstream_api_key_env} is required")

    app = build_app(Path(args.workdir), args.upstream_protocol, args.upstream_base_url, key, args.timeout)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
