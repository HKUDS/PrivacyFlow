#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import httpx

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.materialization_engine import MaterializationEngine
from gateway.mapping_store import MappingStore
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.server import create_app
from gateway.upstream_client import UpstreamClient


class CapturingUpstream:
    def __init__(self, response_text: str) -> None:
        self.response_text = response_text
        self.payloads: list[Any] = []

    async def request_json(self, method: str, path: str, payload: Any | None = None) -> tuple[int, dict[str, str], Any]:
        self.payloads.append(payload)
        return 200, {"content-type": "application/json"}, {"choices": [{"message": {"content": self.response_text}}]}


async def probe_proxy_redaction(tmp: Path) -> dict[str, Any]:
    fake = CapturingUpstream("model echoed sk-proj-abcdefghijklmnopqrstuvwxyz123456")
    cfg = GatewayConfig(
        database_path=str(tmp / "state.sqlite3"),
        audit_log_path=str(tmp / "audit.jsonl"),
        signing_secret="blackbox-secret",
        local_api_keys={"local"},
        workspace_id="blackbox",
        upstream=UpstreamConfig(base_url="https://example.invalid", api_key="unused"),
    )
    app = create_app(cfg, fake)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://apg.local") as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer local", "X-APG-Session-ID": "sess_blackbox"},
            json={
                "model": "blackbox",
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "email howard@example.com path /Users/howard/private/project "
                            "key sk-proj-abcdefghijklmnopqrstuvwxyz123456"
                        ),
                    }
                ],
                "metadata": {"nested": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890"},
            },
        )
    upstream_text = json.dumps(fake.payloads)
    returned_text = response.text
    audit_text = (tmp / "audit.jsonl").read_text(encoding="utf-8")
    return {
        "name": "proxy_redaction_blackbox",
        "ok": all(
            [
                response.status_code == 200,
                "sk-proj-" not in upstream_text,
                "howard@example.com" not in upstream_text,
                "/Users/howard/private" not in upstream_text,
                "Authorization: Bearer" not in upstream_text,
                "sk-proj-" not in returned_text,
                "sk-proj-" not in audit_text,
            ]
        ),
        "evidence": {
            "status_code": response.status_code,
            "upstream_contains_raw_secret": "sk-proj-" in upstream_text,
            "response_contains_raw_secret": "sk-proj-" in returned_text,
            "audit_contains_raw_secret": "sk-proj-" in audit_text,
        },
    }


def probe_placeholder_blackbox(tmp: Path) -> dict[str, Any]:
    store = MappingStore(str(tmp / "placeholder.sqlite3"))
    signer = PlaceholderSigner("blackbox-secret", "blackbox")
    rec = store.upsert_mapping(
        session_id="sess_a",
        workspace_id="blackbox",
        scope="workspace",
        kind="path",
        subtype="local_path",
        value="/Users/howard/project",
        store_value=True,
        materialization_class="path",
    )
    valid = signer.parse(signer.issue("path", rec.handle_id, "sess_a") + "/src/main.py")[0]
    traversal_parsed = signer.parse(signer.issue("path", rec.handle_id, "sess_a") + "/../../.ssh/id_rsa")
    fake = signer.parse("<APG:v1:path:path_fake:sess_a:123:badmac>")[0]
    engine = MaterializationEngine(store, signer, PolicyEngine(), "blackbox")
    valid_result = engine.materialize_placeholder(valid, session_id="sess_a", sink_type="local_tool")
    fake_result = engine.materialize_placeholder(fake, session_id="sess_a", sink_type="local_tool")
    return {
        "name": "placeholder_blackbox",
        "ok": valid_result.allowed and not traversal_parsed and not fake_result.allowed,
        "evidence": {
            "valid_suffix_allowed": valid_result.allowed,
            "traversal_blocked_at_parse": len(traversal_parsed) == 0,
            "fake_error": fake_result.error_code,
        },
    }


def probe_deepseek_path_mapping() -> dict[str, Any]:
    client = UpstreamClient(UpstreamConfig(base_url="https://api.deepseek.com", api_key="unused", strip_local_v1=True))
    return {
        "name": "deepseek_path_mapping_blackbox",
        "ok": client.upstream_path("/v1/chat/completions") == "/chat/completions",
        "evidence": {"mapped_path": client.upstream_path("/v1/chat/completions")},
    }


async def main_async() -> int:
    result = await run_all_probes()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["ok"] else 1


async def run_all_probes() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="apg-blackbox-probe-") as d:
        tmp = Path(d)
        results = [
            await probe_proxy_redaction(tmp),
            probe_placeholder_blackbox(tmp),
            probe_deepseek_path_mapping(),
        ]
    return {"ok": all(r["ok"] for r in results), "results": results}


def main() -> None:
    raise SystemExit(asyncio.run(main_async()))


if __name__ == "__main__":
    main()
