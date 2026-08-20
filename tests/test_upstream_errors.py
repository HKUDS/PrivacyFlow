from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import create_app
from gateway.upstream_client import UpstreamClient
from gateway.upstream_protocol import OPENAI_RESPONSES


class _ExplodingUpstream:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    async def request_json(self, method, path, payload=None):
        raise self.exc

    async def stream_request(self, method, path, payload=None):
        raise self.exc


class _ModelsUpstream:
    def __init__(self, status: int, content_type: str, body) -> None:
        self.response = status, {"content-type": content_type, "x-request-id": "models-test"}, body

    async def request_json(self, method, path, payload=None):
        assert method == "GET"
        assert path == "/v1/models"
        return self.response


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
    assert body["error"]["code"] == "PF_UPSTREAM_UNREACHABLE"
    assert body["error"]["retryable"] is True
    # Must not leak upstream host or traceback in body.
    assert "traceback" not in resp.text.lower()
    assert "upstream/" not in resp.text


def test_upstream_timeout_returns_504(tmp_path) -> None:
    exc = httpx.TimeoutException("timed out")
    client = TestClient(create_app(_cfg(tmp_path), _ExplodingUpstream(exc)))
    resp = client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"messages": [{"content": "hello"}]})
    assert resp.status_code == 504
    assert resp.json()["error"]["code"] == "PF_UPSTREAM_TIMEOUT"


def test_upstream_models_timeout_returns_504(tmp_path) -> None:
    exc = httpx.ConnectError("nope")
    client = TestClient(create_app(_cfg(tmp_path), _ExplodingUpstream(exc)))
    resp = client.get("/v1/models", headers={"Authorization": "Bearer local"})
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == "PF_UPSTREAM_UNREACHABLE"


def test_upstream_models_are_normalized_for_agent_clients(tmp_path) -> None:
    upstream = _ModelsUpstream(
        200,
        "application/json",
        {"models": ["model-b", {"name": "model-a"}, {"id": "model-b"}]},
    )
    client = TestClient(create_app(_cfg(tmp_path), upstream))

    resp = client.get(
        "/v1/models?client_version=0.146.0",
        headers={"Authorization": "Bearer local"},
    )

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-request-id"] == "models-test"
    assert resp.json() == {
        "object": "list",
        "data": [
            {
                "type": "model",
                "object": "model",
                "id": "model-b",
                "display_name": "model-b",
                "created": 0,
                "created_at": "1970-01-01T00:00:00Z",
                "owned_by": "upstream",
            },
            {
                "type": "model",
                "object": "model",
                "id": "model-a",
                "display_name": "model-a",
                "created": 0,
                "created_at": "1970-01-01T00:00:00Z",
                "owned_by": "upstream",
            },
        ],
        "has_more": False,
        "first_id": "model-b",
        "last_id": "model-a",
    }


def test_agent_models_are_parsable_by_anthropic_style_clients(tmp_path) -> None:
    upstream = _ModelsUpstream(
        200,
        "application/json",
        {"data": [{"id": "claude-test"}, {"id": "claude-test-2"}]},
    )
    client = TestClient(create_app(_cfg(tmp_path), upstream))

    resp = client.get(
        "/v1/models",
        headers={
            "Authorization": "Bearer local",
            "x-api-key": "local",
            "anthropic-version": "2023-06-01",
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["object"] == "list"
    assert body["has_more"] is False
    assert body["first_id"] == "claude-test"
    assert body["last_id"] == "claude-test-2"
    assert all(item["type"] == "model" and item["display_name"] == item["id"] for item in body["data"])


@pytest.mark.parametrize("status", [404, 405, 501])
def test_unsupported_upstream_model_list_returns_compatible_empty_list(tmp_path, status: int) -> None:
    upstream = _ModelsUpstream(status, "application/json", {"error": {"message": "unsupported"}})
    client = TestClient(create_app(_cfg(tmp_path), upstream))

    resp = client.get("/v1/models", headers={"Authorization": "Bearer local"})

    assert resp.status_code == 200
    assert resp.json() == {
        "object": "list",
        "data": [],
        "has_more": False,
        "first_id": None,
        "last_id": None,
    }


def test_non_json_upstream_model_list_returns_compatible_empty_list(tmp_path) -> None:
    upstream = _ModelsUpstream(
        200,
        "text/html; charset=utf-8",
        {"error": {"message": "Upstream returned non-JSON response", "status_code": 200}},
    )
    client = TestClient(create_app(_cfg(tmp_path), upstream))

    resp = client.get("/v1/models", headers={"Authorization": "Bearer local"})

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json() == {
        "object": "list",
        "data": [],
        "has_more": False,
        "first_id": None,
        "last_id": None,
    }


def test_agent_models_proxy_requests_standard_v1_route_for_root_base_url(tmp_path) -> None:
    captured: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        return httpx.Response(200, json={"data": [{"id": "deepseek-chat"}]})

    upstream_config = UpstreamConfig(
        base_url="https://upstream.example",
        api_key="provider-key",
        protocol=OPENAI_RESPONSES,
        strip_local_v1=True,
    )
    upstream = UpstreamClient(upstream_config, transport=httpx.MockTransport(handler))
    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=upstream_config,
    )

    with TestClient(create_app(cfg, upstream)) as client:
        resp = client.get(
            "/v1/models?client_version=0.146.0",
            headers={"Authorization": "Bearer local"},
        )

    assert captured == ["https://upstream.example/v1/models"]
    assert resp.status_code == 200
    assert resp.json() == {
        "object": "list",
        "data": [
            {
                "type": "model",
                "object": "model",
                "id": "deepseek-chat",
                "display_name": "deepseek-chat",
                "created": 0,
                "created_at": "1970-01-01T00:00:00Z",
                "owned_by": "upstream",
            }
        ],
        "has_more": False,
        "first_id": "deepseek-chat",
        "last_id": "deepseek-chat",
    }


def test_agent_models_proxy_does_not_duplicate_existing_v1_suffix(tmp_path) -> None:
    captured: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        return httpx.Response(200, json={"data": [{"id": "model-v1"}]})

    upstream_config = UpstreamConfig(
        base_url="https://upstream.example/v1",
        api_key="provider-key",
        protocol=OPENAI_RESPONSES,
        strip_local_v1=True,
    )
    upstream = UpstreamClient(upstream_config, transport=httpx.MockTransport(handler))
    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=upstream_config,
    )

    with TestClient(create_app(cfg, upstream)) as client:
        resp = client.get("/v1/models", headers={"Authorization": "Bearer local"})

    assert captured == ["https://upstream.example/v1/models"]
    assert resp.status_code == 200
    assert resp.json()["data"][0]["id"] == "model-v1"


def test_upstream_model_list_auth_failure_is_not_hidden(tmp_path) -> None:
    body = {"error": {"message": "invalid upstream key"}}
    client = TestClient(create_app(_cfg(tmp_path), _ModelsUpstream(401, "application/json", body)))

    resp = client.get("/v1/models", headers={"Authorization": "Bearer local"})

    assert resp.status_code == 401
    assert resp.json() == body


def test_upstream_audit_log_records_error_phase(tmp_path) -> None:
    audit = tmp_path / "audit.jsonl"
    exc = httpx.ConnectError("nope")
    client = TestClient(create_app(_cfg(tmp_path, ) if False else GatewayConfig(database_path=str(tmp_path / "state.sqlite3"), audit_log_path=str(audit), signing_secret="secret", local_api_keys={"local"}, upstream=UpstreamConfig(api_key="up")), _ExplodingUpstream(exc)))
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer local"}, json={"messages": [{"content": "hello"}]})
    lines = audit.read_text().splitlines()
    assert any('"phase": "upstream_error"' in line and '"code": "PF_UPSTREAM_UNREACHABLE"' in line for line in lines)
