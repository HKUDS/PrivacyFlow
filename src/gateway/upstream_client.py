from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx

from gateway.config import UpstreamConfig


class UpstreamClient:
    def __init__(self, config: UpstreamConfig) -> None:
        self.config = config

    def upstream_path(self, path: str) -> str:
        if self.config.strip_local_v1 and path.startswith("/v1/"):
            return path.removeprefix("/v1")
        return path

    def update_config(self, config: UpstreamConfig) -> None:
        self.config = config

    async def request_json(self, method: str, path: str, payload: Any | None = None) -> tuple[int, dict[str, str], Any]:
        headers = {"Authorization": f"Bearer {self.config.api_key}", "Content-Type": "application/json"}
        upstream_path = self.upstream_path(path)
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            resp = await client.request(method, f"{self.config.base_url}{upstream_path}", headers=headers, json=payload)
        content_type = resp.headers.get("content-type", "")
        if "application/json" in content_type:
            body: Any = resp.json()
        else:
            body = {"error": {"message": "Upstream returned non-JSON response", "status_code": resp.status_code}}
        return resp.status_code, {"content-type": "application/json"}, body

    async def stream_request(self, method: str, path: str, payload: Any | None = None) -> tuple[int, dict[str, str], AsyncIterator[bytes]]:
        headers = {"Authorization": f"Bearer {self.config.api_key}", "Content-Type": "application/json"}
        upstream_path = self.upstream_path(path)
        client = httpx.AsyncClient(timeout=self.config.timeout_seconds)
        stream = client.stream(method, f"{self.config.base_url}{upstream_path}", headers=headers, json=payload)
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
                await client.aclose()

        return resp.status_code, {"content-type": resp.headers.get("content-type", "text/event-stream")}, body()
