from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from gateway.config import UpstreamConfig
from gateway.upstream_protocol import (
    ANTHROPIC_MESSAGES,
    canonical_upstream_protocol,
    upstream_protocol_for_path,
)


_SAFE_RESPONSE_HEADERS = (
    "x-request-id",
    "request-id",
    "openai-request-id",
    "x-correlation-id",
    "trace-id",
    "x-trace-id",
)

_TERMINAL_API_PATHS = (
    "/chat/completions",
    "/responses",
    "/messages",
    "/models",
)


def _terminal_api_path(path: str) -> str:
    normalized = path.rstrip("/")
    return next((suffix for suffix in _TERMINAL_API_PATHS if normalized.endswith(suffix)), "")


class UpstreamClient:
    def __init__(self, config: UpstreamConfig, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.config = config
        self.transport = transport
        self._client: httpx.AsyncClient | None = None

    def upstream_path(self, path: str) -> str:
        request_protocol = upstream_protocol_for_path(path) or canonical_upstream_protocol(self.config.protocol)
        base_path = urlsplit(self.config.base_url).path.rstrip("/")
        if path.startswith("/v1/") and base_path.endswith("/v1"):
            return path.removeprefix("/v1")
        if request_protocol != ANTHROPIC_MESSAGES and self.config.strip_local_v1 and path.startswith("/v1/"):
            return path.removeprefix("/v1")
        return path

    def update_config(self, config: UpstreamConfig) -> None:
        if config == self.config:
            return
        previous = self._client
        self.config = config
        self._client = None
        if previous is not None:
            self._schedule_close(previous)

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    def _schedule_close(self, client: httpx.AsyncClient) -> None:
        try:
            asyncio.get_running_loop().create_task(client.aclose())
        except RuntimeError:
            pass

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(**self._client_kwargs())
        return self._client

    def _client_kwargs(self) -> dict[str, Any]:
        """Build httpx client options without ambient environment proxies."""
        kwargs: dict[str, Any] = {
            "timeout": self.config.timeout_seconds,
            "trust_env": False,
        }
        if self.transport is not None:
            kwargs["transport"] = self.transport
        if self.config.proxy:
            kwargs["proxy"] = self.config.proxy
        return kwargs

    def resolve_upstream_url(self, upstream_path: str) -> str:
        """Resolve a route against either an API root or a configured full endpoint."""
        request_protocol = upstream_protocol_for_path(upstream_path)
        requested_terminal = _terminal_api_path(urlsplit(upstream_path).path)
        override = self.config.endpoint_overrides.get(request_protocol, "")
        if override and requested_terminal != "/models":
            return override
        base_url = self.config.base_url.rstrip("/")
        parsed = urlsplit(base_url)
        base_path = parsed.path.rstrip("/")
        base_terminal = _terminal_api_path(base_path)
        if base_terminal and requested_terminal:
            sibling_path = f"{base_path[:-len(base_terminal)]}{requested_terminal}" or "/"
            return urlunsplit((parsed.scheme, parsed.netloc, sibling_path, "", ""))
        separator = "" if upstream_path.startswith("/") else "/"
        return f"{base_url}{separator}{upstream_path}"

    async def request_json(self, method: str, path: str, payload: Any | None = None) -> tuple[int, dict[str, str], Any]:
        return await self.request_json_upstream_path(method, self.upstream_path(path), payload)

    async def request_json_upstream_path(
        self,
        method: str,
        upstream_path: str,
        payload: Any | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        """Request an already-resolved upstream path without applying local route rewriting."""
        headers = self._headers(upstream_protocol_for_path(upstream_path))
        client = self._get_client()
        resp = await client.request(method, self.resolve_upstream_url(upstream_path), headers=headers, json=payload)
        content_type = resp.headers.get("content-type", "")
        if "application/json" in content_type:
            body: Any = resp.json()
        else:
            body = {"error": {"message": "Upstream returned non-JSON response", "status_code": resp.status_code}}
        return resp.status_code, self._response_headers(resp, "application/json"), body

    async def stream_request(self, method: str, path: str, payload: Any | None = None) -> tuple[int, dict[str, str], AsyncIterator[bytes]]:
        upstream_path = self.upstream_path(path)
        headers = self._headers(upstream_protocol_for_path(path))
        client = self._get_client()
        stream = client.stream(method, self.resolve_upstream_url(upstream_path), headers=headers, json=payload)
        try:
            resp = await stream.__aenter__()
        except Exception:
            await client.aclose()
            raise

        async def body() -> AsyncIterator[bytes]:
            try:
                async for chunk in resp.aiter_raw():
                    yield chunk
            finally:
                await stream.__aexit__(None, None, None)

        return resp.status_code, self._response_headers(resp, "text/event-stream"), body()

    @staticmethod
    def _response_headers(response: httpx.Response, default_content_type: str) -> dict[str, str]:
        headers = {"content-type": response.headers.get("content-type", default_content_type)}
        for name in _SAFE_RESPONSE_HEADERS:
            value = response.headers.get(name)
            if value and len(value) <= 512 and all(32 <= ord(char) < 127 for char in value):
                headers[name] = value
        return headers

    def _headers(self, protocol: str = "") -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        effective_protocol = protocol or canonical_upstream_protocol(self.config.protocol)
        if effective_protocol == ANTHROPIC_MESSAGES:
            headers["x-api-key"] = self.config.api_key
            headers["anthropic-version"] = "2023-06-01"
        else:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers
