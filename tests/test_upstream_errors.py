from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import create_app


class _ExplodingUpstream:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    async def request_json(self, method, path, payload=None):
        raise self.exc

    async def stream_request(self, method, path, payload=None):
        raise self.exc


def _cfg(tmp_path):
    return GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(base_url="https://upstream", api_key="up"),
    )


def test_upstream_connect_error_returns_502_without_traceback(tmp_path) -> None:
    exc = httpx.ConnectError("failed to connect to https://upstream/")
    client = TestClient(create_app(_cfg(tmp_path), _ExplodingUpstream(exc)))
    resp = client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"messages": [{"content": "hello"}]})
    assert resp.status_code == 502
    body = resp.json()
    assert body["error"]["code"] == "APG_UPSTREAM_UNREACHABLE"
    assert body["error"]["retryable"] is True
    # Must not leak upstream host or traceback in body.
    assert "traceback" not in resp.text.lower()
    assert "upstream/" not in resp.text


def test_upstream_timeout_returns_504(tmp_path) -> None:
    exc = httpx.TimeoutException("timed out")
    client = TestClient(create_app(_cfg(tmp_path), _ExplodingUpstream(exc)))
    resp = client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"messages": [{"content": "hello"}]})
    assert resp.status_code == 504
    assert resp.json()["error"]["code"] == "APG_UPSTREAM_TIMEOUT"


def test_upstream_models_timeout_returns_504(tmp_path) -> None:
    exc = httpx.ConnectError("nope")
    client = TestClient(create_app(_cfg(tmp_path), _ExplodingUpstream(exc)))
    resp = client.get("/v1/models", headers={"Authorization": "Bearer local"})
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == "APG_UPSTREAM_UNREACHABLE"


def test_upstream_audit_log_records_error_phase(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"
    exc = httpx.ConnectError("nope")
    client = TestClient(create_app(_cfg(tmp_path, ) if False else GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(audit), signing_secret="secret", local_api_keys={"local"}, upstream=UpstreamConfig(api_key="up")), _ExplodingUpstream(exc)))
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"messages": [{"content": "hello"}]})
    lines = audit.read_text().splitlines()
    assert any('"phase": "upstream_error"' in line and '"code": "APG_UPSTREAM_UNREACHABLE"' in line for line in lines)