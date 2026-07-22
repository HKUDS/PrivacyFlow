from __future__ import annotations

from pathlib import Path
from typing import Any

from gateway.config import UpstreamConfig
from gateway.upstream_client import UpstreamClient

from e2e_agent_tests.scripts.common import append_jsonl


class RecordingUpstreamClient(UpstreamClient):
    def __init__(self, config: UpstreamConfig, upstream_log: Path) -> None:
        super().__init__(config)
        self.upstream_log = upstream_log

    async def request_json(self, method: str, path: str, payload: Any | None = None) -> tuple[int, dict[str, str], Any]:
        append_jsonl(
            self.upstream_log,
            {
                "kind": "real_api_sanitized_upstream_request",
                "method": method,
                "local_path": path,
                "upstream_path": self.upstream_path(path),
                "payload": payload,
            },
        )
        return await super().request_json(method, path, payload)

    async def stream_request(self, method: str, path: str, payload: Any | None = None):
        append_jsonl(
            self.upstream_log,
            {
                "kind": "real_api_sanitized_upstream_stream_request",
                "method": method,
                "local_path": path,
                "upstream_path": self.upstream_path(path),
                "payload": payload,
            },
        )
        return await super().stream_request(method, path, payload)
