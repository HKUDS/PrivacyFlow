from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

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

# A stable, non-secret User-Agent keeps model-list requests distinguishable from
# browser traffic and avoids providers/CDNs rejecting a request with no UA.
DEFAULT_USER_AGENT = "privacyflow"


def _is_json_content_type(value: str) -> bool:
    media_type = value.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or media_type.endswith("+json")


def _terminal_api_path(path: str) -> str:
    normalized = path.rstrip("/")
    return next((suffix for suffix in _TERMINAL_API_PATHS if normalized.endswith(suffix)), "")


def _deepseek_anthropic_root(parsed: SplitResult) -> SplitResult | None:
    """Map DeepSeek's OpenAI root onto the documented Anthropic surface.

    Official Anthropic ``base_url`` is ``https://api.deepseek.com/anthropic``.
    Configuring the OpenAI root with ``anthropic_messages`` would otherwise
    POST ``/v1/messages`` to a path that is not served.
    """
    if parsed.hostname != "api.deepseek.com":
        return None
    parts = [part.lower() for part in parsed.path.split("/") if part]
    if "anthropic" in parts or parts not in ([], ["v1"]):
        return None
    return parsed._replace(path="/anthropic", query="", fragment="")


class UpstreamClient:
    def __init__(self, config: UpstreamConfig, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.config = config
        self.transport = transport
        self._client: httpx.AsyncClient | None = None
        # Clients retired by a config change. They are kept until shutdown so
        # requests that were already streaming on them finish instead of
        # failing with "Cannot send a request, as the client has been closed."
        self._retired_clients: list[httpx.AsyncClient] = []

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
            self._retired_clients.append(previous)

    async def close(self) -> None:
        retired, self._retired_clients = self._retired_clients, []
        for client in retired:
            try:
                await client.aclose()
            except Exception:
                pass
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

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
        parsed_request = urlsplit(upstream_path)
        if parsed_request.scheme in {"http", "https"} and parsed_request.netloc:
            # Model discovery may retry a sibling catalog URL outside the
            # configured protocol prefix (for example DeepSeek's
            # /anthropic/v1/models -> /models). Preserve that absolute target
            # instead of joining it to the configured Base URL a second time.
            return upstream_path
        request_protocol = upstream_protocol_for_path(upstream_path)
        requested_terminal = _terminal_api_path(urlsplit(upstream_path).path)
        override = self.config.endpoint_overrides.get(request_protocol, "")
        if override and requested_terminal != "/models":
            return override
        base_url = self.config.base_url.rstrip("/")
        parsed = urlsplit(base_url)
        effective_protocol = request_protocol or canonical_upstream_protocol(self.config.protocol)
        if effective_protocol == ANTHROPIC_MESSAGES:
            rewritten = _deepseek_anthropic_root(parsed)
            if rewritten is not None:
                parsed = rewritten
                base_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")).rstrip("/")
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
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        """Request an already-resolved upstream path without applying local route rewriting."""
        headers = self._headers(upstream_protocol_for_path(upstream_path))
        if extra_headers:
            headers.update({str(key): str(value) for key, value in extra_headers.items() if str(value).strip()})
        client = self._get_client()
        resp = await client.request(method, self.resolve_upstream_url(upstream_path), headers=headers, json=payload)
        content_type = resp.headers.get("content-type", "")
        try:
            # Some compatible providers omit or mislabel Content-Type. Parse
            # the bounded response body first; callers still use the header to
            # classify a non-JSON error when decoding fails.
            body: Any = resp.json()
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            body = {
                "error": {
                    "message": "Upstream returned malformed JSON response"
                    if _is_json_content_type(content_type)
                    else "Upstream returned non-JSON response",
                    "status_code": resp.status_code,
                }
            }
        return resp.status_code, self._response_headers(resp, "application/json"), body

    async def request_json_model_catalog(
        self,
        upstream_path: str,
    ) -> tuple[int, dict[str, str], Any]:
        """Fetch a provider model catalog with catalog-compatible auth headers.

        A provider can expose Anthropic inference below ``/anthropic`` while its
        OpenAI-compatible ``/models`` resource remains at the host root.  Keep
        the configured Anthropic headers, but also send Bearer auth so that the
        root catalog accepts the same key (the request is still made only to the
        configured upstream target).
        """
        extra_headers: dict[str, str] = {}
        if canonical_upstream_protocol(self.config.protocol) == ANTHROPIC_MESSAGES:
            extra_headers["Authorization"] = f"Bearer {self.config.api_key}"
        return await self.request_json_upstream_path(
            "GET",
            upstream_path,
            extra_headers=extra_headers,
        )

    async def stream_request(self, method: str, path: str, payload: Any | None = None) -> tuple[int, dict[str, str], AsyncIterator[bytes]]:
        upstream_path = self.upstream_path(path)
        headers = self._headers(upstream_protocol_for_path(path))
        client = self._get_client()
        stream = client.stream(method, self.resolve_upstream_url(upstream_path), headers=headers, json=payload)
        # A failed connect here is a transient, per-request failure. Do not
        # close the shared client: doing so breaks every in-flight and later
        # request with "Cannot send a request, as the client has been closed."
        resp = await stream.__aenter__()

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
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        user_agent = str(getattr(self.config, "user_agent", "") or "").strip()
        if len(user_agent) > 256 or any(ord(char) < 32 or ord(char) > 126 for char in user_agent):
            user_agent = ""
        headers["User-Agent"] = (user_agent or DEFAULT_USER_AGENT)[:256]
        effective_protocol = protocol or canonical_upstream_protocol(self.config.protocol)
        if effective_protocol == ANTHROPIC_MESSAGES:
            headers["x-api-key"] = self.config.api_key
            headers["anthropic-version"] = "2023-06-01"
        else:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers
