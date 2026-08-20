from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import gateway.server as server_module
from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import create_app
from gateway.upstream_client import UpstreamClient
from gateway.upstream_protocol import OPENAI_CHAT_COMPLETIONS

from gateway.model_catalog import (
    build_model_catalog_urls,
    fetch_model_catalog,
    normalize_cached_catalog,
    parse_model_catalog,
)
from gateway.model_mapping import build_role_mapping, resolve_role_model, strip_large_context_suffix


def test_catalog_urls_honor_override_and_compatibility_fallbacks() -> None:
    assert build_model_catalog_urls(
        "https://api.deepseek.com/anthropic",
        strip_local_v1=True,
    ) == [
        "https://api.deepseek.com/anthropic/v1/models",
        "https://api.deepseek.com/v1/models",
        "https://api.deepseek.com/models",
    ]
    assert build_model_catalog_urls(
        "https://provider.example/v1/chat/completions",
        models_url="https://catalog.example/models",
    ) == ["https://catalog.example/models"]


def test_catalog_parser_preserves_display_name_but_keeps_actual_id() -> None:
    options, truncated = parse_model_catalog(
        {
            "data": [
                {"id": "vendor/sonnet", "display_name": "Sonnet (1M)", "owned_by": "vendor"},
                {"model": "vendor/haiku"},
                {"id": "vendor/sonnet"},
            ]
        }
    )
    assert not truncated
    assert [item.id for item in options] == ["vendor/sonnet", "vendor/haiku"]
    assert options[0].display_name == "Sonnet (1M)"
    assert options[0].owned_by == "vendor"


def test_catalog_fetch_retries_only_not_found_statuses_and_classifies_empty() -> None:
    calls: list[str] = []

    async def requester(endpoint: str):
        calls.append(endpoint)
        if endpoint.endswith("/v1/models"):
            return 404, {"content-type": "application/json"}, {"error": {"message": "not found"}}
        return 200, {"content-type": "application/json"}, {"data": []}

    result = asyncio.run(fetch_model_catalog(requester, "https://provider.example", strip_local_v1=True))
    assert calls == ["https://provider.example/v1/models", "https://provider.example/models"]
    assert result.error is not None
    assert result.error.code == "PF_UPSTREAM_MODEL_CATALOG_EMPTY"
    assert result.status_code == 200


def test_model_mapping_is_preview_only_and_does_not_change_ids() -> None:
    assert strip_large_context_suffix("claude-sonnet [1M]") == "claude-sonnet"
    mapping = build_role_mapping(["vendor/claude-haiku", "vendor/claude-sonnet", "vendor/claude-opus"])
    assert mapping["sonnet"] == "vendor/claude-sonnet"
    assert resolve_role_model("fable", mapping) == "vendor/claude-opus"


def test_rich_catalog_endpoint_and_unsaved_preview_never_echo_key(tmp_path: Path) -> None:
    seen: list[tuple[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        return httpx.Response(
            200,
            json={"data": [{"id": "vendor/model", "display_name": "Friendly model", "owned_by": "vendor"}]},
        )

    upstream_config = UpstreamConfig(
        base_url="https://provider.example",
        api_key="provider-secret",
        protocol=OPENAI_CHAT_COMPLETIONS,
    )
    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="test-signing-secret",
        local_api_keys={"agent-key"},
        strict_mode=True,
        upstream=upstream_config,
    )
    client_impl = UpstreamClient(upstream_config, transport=httpx.MockTransport(handler))
    with TestClient(create_app(cfg, client_impl)) as client:
        rich = client.get(
            "/api/admin/upstream-configuration/models",
            headers={"X-APG-Model-Catalog": "rich"},
        )
        assert rich.status_code == 200
        assert rich.json()["model_options"] == [
            {"id": "vendor/model", "display_name": "Friendly model", "owned_by": "vendor", "type": "model"}
        ]
        preview = client.post(
            "/api/admin/upstream-configuration/models/preview",
            json={
                "base_url": "https://provider.example",
                "protocol": OPENAI_CHAT_COMPLETIONS,
                "api_key": "provider-secret",
            },
        )
        assert preview.status_code == 200
        assert preview.json()["models"] == ["vendor/model"]
        assert "provider-secret" not in preview.text
        assert "provider-secret" not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert seen


def test_anthropic_catalog_request_keeps_native_headers_and_adds_bearer(tmp_path: Path) -> None:
    captured: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.update({key.lower(): value for key, value in request.headers.items()})
        return httpx.Response(200, json={"data": [{"id": "deepseek-v4"}]})

    config = UpstreamConfig(
        base_url="https://api.deepseek.com/anthropic",
        api_key="provider-secret",
        protocol="anthropic_messages",
    )
    client = UpstreamClient(config, transport=httpx.MockTransport(handler))

    async def request() -> None:
        await client.request_json_model_catalog("https://api.deepseek.com/models")
        await client.close()

    asyncio.run(request())
    assert captured["authorization"] == "Bearer provider-secret"
    assert captured["x-api-key"] == "provider-secret"
    assert captured["anthropic-version"] == "2023-06-01"
    assert captured["user-agent"] == "privacyflow"


def test_unsaved_anthropic_preview_uses_catalog_auth_headers(tmp_path: Path, monkeypatch) -> None:
    captured: list[dict[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append({key.lower(): value for key, value in request.headers.items()})
        return httpx.Response(200, json={"data": [{"id": "deepseek-v4"}]})

    config = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="test-signing-secret",
        local_api_keys={"agent-key"},
        strict_mode=True,
        upstream=UpstreamConfig(
            base_url="https://api.deepseek.com/anthropic",
            api_key="active-key",
            protocol="anthropic_messages",
        ),
    )
    client_impl = UpstreamClient(config.upstream, transport=httpx.MockTransport(handler))

    class PreviewClient(UpstreamClient):
        def __init__(self, preview_config):
            super().__init__(preview_config, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(server_module, "UpstreamClient", PreviewClient)
    with TestClient(create_app(config, client_impl)) as client:
        response = client.post(
            "/api/admin/upstream-configuration/models/preview",
            json={
                "base_url": "https://api.deepseek.com/anthropic",
                "protocol": "anthropic_messages",
                "api_key": "preview-key",
            },
        )
    assert response.status_code == 200
    assert response.json()["models"] == ["deepseek-v4"]
    assert captured
    assert captured[0]["authorization"] == "Bearer preview-key"
    assert captured[0]["x-api-key"] == "preview-key"


def test_cached_catalog_error_does_not_replay_arbitrary_text() -> None:
    cached = normalize_cached_catalog(
        {
            "fetched_at": 1,
            "source_endpoint": "https://provider.example/v1/models?secret=hidden",
            "error": {
                "code": "APG_UPSTREAM_MODELS_FAILED",
                "category": "upstream",
                "message": "provider-secret must never be echoed",
                "status_code": 500,
            },
        }
    )
    assert cached is not None
    assert "provider-secret" not in str(cached)
    assert cached["error"]["message"] == "The model catalog could not be loaded."
    assert cached["source_endpoint"] == "https://provider.example/v1/models"
