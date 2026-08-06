from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

import gateway.upstream_client as upstream_client_module
from gateway.cli.launcher import (
    LauncherConfigError,
    apply_launcher_environment,
    prepare_launcher_config,
    save_launcher_upstream_profile,
)
from gateway.config import UpstreamConfig, load_config
from gateway.upstream_client import UpstreamClient


class RecordingAsyncClient(httpx.AsyncClient):
    calls: list[dict[str, Any]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        type(self).calls.append(kwargs)
        super().__init__(*args, **kwargs)


class FakeResponseClient(httpx.AsyncClient):
    calls: list[dict[str, Any]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        type(self).calls.append(kwargs)
        super().__init__(*args, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        return httpx.Response(200, json={"ok": True}, request=httpx.Request(method, url))

    def stream(self, method: str, url: str, **kwargs: Any) -> Any:
        class _FakeResponse:
            status_code = 200
            headers = {"content-type": "text/event-stream"}

            async def aiter_raw(self) -> Any:
                if False:
                    yield b""

        class _FakeStream:
            async def __aenter__(self) -> _FakeResponse:
                return _FakeResponse()

            async def __aexit__(self, *args: Any) -> None:
                return None

        return _FakeStream()


def _json_handler(body: dict[str, Any]):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body, request=request)

    return handler


def test_upstream_client_ignores_environment_proxies_by_default(monkeypatch) -> None:
    RecordingAsyncClient.calls = []
    monkeypatch.setattr(upstream_client_module.httpx, "AsyncClient", RecordingAsyncClient)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")

    upstream = UpstreamClient(
        UpstreamConfig(base_url="https://provider.example", api_key=""),
        transport=httpx.MockTransport(_json_handler({"ok": True})),
    )
    status, _, body = asyncio.run(upstream.request_json("POST", "/v1/chat/completions", {"model": "x"}))

    assert status == 200
    assert body == {"ok": True}
    kwargs = RecordingAsyncClient.calls[0]
    assert kwargs["trust_env"] is False
    assert "proxy" not in kwargs
    assert kwargs["transport"] is not None


def test_upstream_client_uses_explicit_proxy_when_configured(monkeypatch) -> None:
    FakeResponseClient.calls = []
    monkeypatch.setattr(upstream_client_module.httpx, "AsyncClient", FakeResponseClient)

    upstream = UpstreamClient(
        UpstreamConfig(
            base_url="https://provider.example",
            api_key="",
            proxy="http://127.0.0.1:7890",
        )
    )
    status, _, body = asyncio.run(upstream.request_json("POST", "/v1/chat/completions", {"model": "x"}))
    assert status == 200
    assert body == {"ok": True}
    kwargs = FakeResponseClient.calls[0]
    assert kwargs["trust_env"] is False
    assert kwargs["proxy"] == "http://127.0.0.1:7890"


def test_upstream_stream_client_uses_explicit_proxy_when_configured(monkeypatch) -> None:
    FakeResponseClient.calls = []
    monkeypatch.setattr(upstream_client_module.httpx, "AsyncClient", FakeResponseClient)

    upstream = UpstreamClient(
        UpstreamConfig(
            base_url="https://provider.example",
            api_key="",
            proxy="http://127.0.0.1:7890",
        )
    )

    async def consume() -> tuple[int, list[bytes]]:
        status, _, chunks = await upstream.stream_request("POST", "/v1/chat/completions", {"model": "x"})
        return status, [chunk async for chunk in chunks]

    status, chunks = asyncio.run(consume())
    assert status == 200
    assert chunks == []
    assert FakeResponseClient.calls[0]["trust_env"] is False
    assert FakeResponseClient.calls[0]["proxy"] == "http://127.0.0.1:7890"


def test_load_config_proxy_from_env(monkeypatch) -> None:
    monkeypatch.setenv("APG_UPSTREAM_PROXY", "http://127.0.0.1:7890")
    monkeypatch.setenv("APG_LOCAL_API_KEYS", "local")
    monkeypatch.setenv("APG_SIGNING_SECRET", "test-signing-secret")
    assert load_config().upstream.proxy == "http://127.0.0.1:7890"


def test_load_config_proxy_from_yaml(tmp_path) -> None:
    config_path = tmp_path / "apg.yaml"
    config_path.write_text(
        "upstream:\n"
        "  base_url: https://provider.example\n"
        "  api_key: k\n"
        "  proxy: http://127.0.0.1:7891\n"
        "strict_mode: false\n",
        encoding="utf-8",
    )
    assert load_config(str(config_path)).upstream.proxy == "http://127.0.0.1:7891"


def test_load_config_default_no_proxy(monkeypatch) -> None:
    monkeypatch.delenv("APG_UPSTREAM_PROXY", raising=False)
    monkeypatch.setenv("APG_LOCAL_API_KEYS", "local")
    monkeypatch.setenv("APG_SIGNING_SECRET", "test-signing-secret")
    assert load_config().upstream.proxy is None


def _write_launcher(tmp_path, profiles: list[dict[str, Any]], active: str = "p1") -> Path:
    path = tmp_path / "launcher.json"
    path.write_text(
        json.dumps({"upstream_profiles": profiles, "active_upstream_profile_id": active}),
        encoding="utf-8",
    )
    return path


def _profile(proxy: str = "") -> dict[str, Any]:
    return {
        "id": "p1",
        "name": "P",
        "protocol": "openai_chat_completions",
        "base_url": "https://provider.example",
        "api_key": "k",
        "proxy": proxy,
    }


def test_launcher_resolves_profile_proxy(tmp_path) -> None:
    path = _write_launcher(tmp_path, [_profile("http://127.0.0.1:7890")])
    prepared = prepare_launcher_config(path, environ={})
    assert prepared["_resolved_upstream_proxy"] == "http://127.0.0.1:7890"
    assert prepared["upstream_profiles"][0]["proxy"] == "http://127.0.0.1:7890"


def test_launcher_env_proxy_overrides_profile(tmp_path) -> None:
    path = _write_launcher(tmp_path, [_profile("http://127.0.0.1:7890")])
    prepared = prepare_launcher_config(path, environ={"APG_UPSTREAM_PROXY": "http://proxy.example:8080"})
    assert prepared["_resolved_upstream_proxy"] == "http://proxy.example:8080"


def test_apply_launcher_environment_exports_proxy(tmp_path) -> None:
    path = _write_launcher(tmp_path, [_profile("http://127.0.0.1:7890")])
    prepared = prepare_launcher_config(path, environ={})
    environment: dict[str, str] = {}
    apply_launcher_environment(prepared, environ=environment)
    assert environment["APG_UPSTREAM_PROXY"] == "http://127.0.0.1:7890"


def test_save_profile_preserves_existing_proxy_when_omitted(tmp_path) -> None:
    path = _write_launcher(tmp_path, [_profile("http://127.0.0.1:7890")])
    saved = save_launcher_upstream_profile(
        path,
        profile_id="p1",
        name="P",
        protocol="openai_chat_completions",
        base_url="https://provider.example",
        api_key="",
    )
    assert saved["proxy"] == "http://127.0.0.1:7890"


def test_save_profile_clears_proxy_with_empty_string(tmp_path) -> None:
    path = _write_launcher(tmp_path, [_profile("http://127.0.0.1:7890")])
    saved = save_launcher_upstream_profile(
        path,
        profile_id="p1",
        name="P",
        protocol="openai_chat_completions",
        base_url="https://provider.example",
        api_key="",
        proxy="",
    )
    assert saved["proxy"] == ""


def test_save_profile_rejects_invalid_proxy(tmp_path) -> None:
    path = _write_launcher(tmp_path, [_profile()])
    with pytest.raises(LauncherConfigError):
        save_launcher_upstream_profile(
            path,
            profile_id="p1",
            name="P",
            protocol="openai_chat_completions",
            base_url="https://provider.example",
            api_key="",
            proxy="ftp://proxy.example",
        )


def test_upstream_client_reuses_shared_connection(monkeypatch) -> None:
    RecordingAsyncClient.calls = []
    monkeypatch.setattr(upstream_client_module.httpx, "AsyncClient", RecordingAsyncClient)
    upstream = UpstreamClient(
        UpstreamConfig(base_url="https://provider.example", api_key=""),
        transport=httpx.MockTransport(_json_handler({"ok": True})),
    )

    async def run() -> None:
        for _ in range(3):
            status, _, body = await upstream.request_json("POST", "/v1/chat/completions", {"model": "x"})
            assert status == 200
            assert body == {"ok": True}
        await upstream.close()

    asyncio.run(run())
    assert len(RecordingAsyncClient.calls) == 1


def test_upstream_client_recreates_client_after_update_config(monkeypatch) -> None:
    FakeResponseClient.calls = []
    monkeypatch.setattr(upstream_client_module.httpx, "AsyncClient", FakeResponseClient)
    upstream = UpstreamClient(
        UpstreamConfig(base_url="https://provider.example", api_key=""),
    )

    async def run() -> None:
        status, _, _ = await upstream.request_json("POST", "/v1/chat/completions", {"model": "x"})
        assert status == 200
        upstream.update_config(
            UpstreamConfig(
                base_url="https://provider.example",
                api_key="",
                proxy="http://127.0.0.1:7890",
            )
        )
        status, _, _ = await upstream.request_json("POST", "/v1/chat/completions", {"model": "x"})
        assert status == 200
        await upstream.close()

    asyncio.run(run())
    assert len(FakeResponseClient.calls) == 2
    assert FakeResponseClient.calls[1]["proxy"] == "http://127.0.0.1:7890"


def test_upstream_client_recreates_client_after_close(monkeypatch) -> None:
    RecordingAsyncClient.calls = []
    monkeypatch.setattr(upstream_client_module.httpx, "AsyncClient", RecordingAsyncClient)
    upstream = UpstreamClient(
        UpstreamConfig(base_url="https://provider.example", api_key=""),
        transport=httpx.MockTransport(_json_handler({"ok": True})),
    )

    async def run() -> None:
        status, _, _ = await upstream.request_json("POST", "/v1/chat/completions", {"model": "x"})
        assert status == 200
        await upstream.close()
        status, _, _ = await upstream.request_json("POST", "/v1/chat/completions", {"model": "x"})
        assert status == 200
        await upstream.close()

    asyncio.run(run())
    assert len(RecordingAsyncClient.calls) == 2
