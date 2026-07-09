#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiments.apg_blackbox_probe import run_all_probes


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/probe":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        result = asyncio.run(run_all_probes())
        body = json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8766), Handler)
    print("APG black-box probe server listening on http://127.0.0.1:8766/probe", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
