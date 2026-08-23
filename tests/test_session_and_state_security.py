from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from fastapi.responses import StreamingResponse

from gateway.audit_logger import AuditLogger
from gateway.config import GatewayConfig, UpstreamConfig
from gateway.detector_manager import DetectorManager
from gateway.detectors.flow import FlowModule
from gateway.mapping_store import MappingStore
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import RedactionEngine
from gateway.server import create_app
from gateway.state.session_manager import SessionManager, SessionScopeError


class EmptyUpstream:
    async def request_json(self, method, path, payload=None):
        return 200, {"content-type": "application/json"}, {"choices": [{"message": {"content": "ok"}}]}


def test_gateway_rejects_all_agent_requests_when_key_set_is_empty(tmp_path) -> None:
    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys=set(),
        upstream=UpstreamConfig(api_key="provider-key"),
    )
    with TestClient(create_app(cfg, EmptyUpstream())) as client:
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer arbitrary"},
            json={"messages": [{"content": "hello"}]},
        )
    assert response.status_code == 401


def test_non_loopback_bind_disables_admin_plane_without_disabling_agent_proxy(tmp_path) -> None:
    cfg = GatewayConfig(
        bind_host="0.0.0.0",
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(api_key="provider-key"),
    )
    with pytest.warns(RuntimeWarning, match="were disabled"):
        app = create_app(cfg, EmptyUpstream())
    with TestClient(app) as client:
        assert client.get("/api/admin/overview").status_code == 403
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer local"},
            json={"messages": [{"content": "hello"}]},
        )
        assert response.status_code == 200


def test_admin_plane_rejects_non_loopback_peer_host_and_origin(tmp_path) -> None:
    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(api_key="provider-key"),
    )
    app = create_app(cfg, EmptyUpstream())
    with TestClient(
        app,
        base_url="http://127.0.0.1:8765",
        client=("127.0.0.1", 50000),
    ) as client:
        assert client.get("/api/admin/overview").status_code == 200
        assert client.get("/api/admin/connection").json()["api_key"] == "local"
        assert client.get("/api/admin/overview", headers={"Host": "attacker.example:8765"}).status_code == 403
        assert client.get("/api/admin/overview", headers={"Origin": "https://attacker.example"}).status_code == 403
        assert client.get(
            "/api/admin/overview",
            headers={"Origin": "http://127.0.0.1:8765"},
        ).status_code == 200
    with TestClient(
        app,
        base_url="http://127.0.0.1:8765",
        client=("192.0.2.10", 50000),
    ) as remote_client:
        assert remote_client.get("/api/admin/overview").status_code == 403


def test_namespace_middleware_preserves_invalid_json_response_body(tmp_path) -> None:
    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(api_key="provider-key"),
    )
    app = create_app(cfg, EmptyUpstream())

    async def invalid_json() -> StreamingResponse:
        async def body():
            yield b"not-json-upstream-error"

        return StreamingResponse(body(), status_code=502, media_type="application/json")

    app.add_api_route("/_test/invalid-json", invalid_json, methods=["GET"])
    with TestClient(app) as client:
        response = client.get("/_test/invalid-json")
    assert response.status_code == 502
    assert response.content == b"not-json-upstream-error"


def test_detector_diagnostics_are_isolated_between_concurrent_requests() -> None:
    barrier = Barrier(2)

    class ConcurrentDetector:
        def detect(self, block, normalized):
            del normalized
            barrier.wait(timeout=2)
            if block.text == "explode":
                raise ValueError("expected test failure")
            return []

    manager = DetectorManager()
    manager.hierarchical.flow.modules = [
        FlowModule("concurrent", "python_plugin", ConcurrentDetector()),
    ]

    def scan(text: str) -> dict:
        manager.reset_diagnostics()
        manager.scan_findings(text)
        return manager.diagnostics()[0]

    with ThreadPoolExecutor(max_workers=2) as executor:
        healthy = executor.submit(scan, "healthy")
        failing = executor.submit(scan, "explode")
    assert healthy.result()["status"] == "ok"
    assert failing.result()["status"] == "error"


def test_explicit_session_is_bound_to_local_api_key(tmp_path) -> None:
    manager = SessionManager(str(tmp_path / "sessions.sqlite3"))
    session_id = manager.session_for_key("key-a")
    assert manager.session_for_key("key-a", session_id) == session_id
    with pytest.raises(SessionScopeError, match="unavailable"):
        manager.session_for_key("key-b", session_id)


def test_expired_explicit_session_is_rejected_and_implicit_session_rotates(tmp_path) -> None:
    manager = SessionManager(str(tmp_path / "sessions.sqlite3"))
    expired = manager.session_for_key("key-a", ttl_seconds=-1)
    with pytest.raises(SessionScopeError):
        manager.session_for_key("key-a", expired)
    replacement = manager.session_for_key("key-a")
    assert replacement != expired


def test_api_returns_safe_403_for_cross_key_session(tmp_path) -> None:
    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"key-a", "key-b"},
        upstream=UpstreamConfig(api_key="provider-key"),
    )
    client = TestClient(create_app(cfg, EmptyUpstream()))
    first = client.post("/v1/chat/completions", headers={"Authorization": "Bearer key-a"}, json={"messages": [{"content": "hello"}]})
    assert first.status_code == 200
    request_event = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[0])
    session_id = request_event["session_id"]
    blocked = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer key-b", "X-APG-Session-ID": session_id},
        json={"messages": [{"content": "hello"}]},
    )
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["code"] == "APG_SESSION_SCOPE_MISMATCH"
    assert blocked.json()["detail"]["retryable"] is False


def test_path_alias_restores_after_redactor_restart_but_not_cross_session(tmp_path) -> None:
    db = str(tmp_path / "state.sqlite3")
    first_store = MappingStore(db)
    first = RedactionEngine(DetectorManager(), first_store, PlaceholderSigner("secret", "ws"), PolicyEngine(), "ws")
    raw_path = "/Users/howard/private/project"
    alias, _ = first.sanitize_text(raw_path, "sess-a")
    assert alias.startswith("/workspace/")

    restarted = RedactionEngine(
        DetectorManager(),
        MappingStore(db),
        PlaceholderSigner("secret", "ws"),
        PolicyEngine(),
        "ws",
    )
    restored, _ = restarted.scan_local_text(alias + "/src/app.py", "sess-a")
    assert restored == raw_path + "/src/app.py"
    isolated, _ = restarted.scan_local_text(alias + "/src/app.py", "sess-b")
    assert raw_path not in isolated
    assert alias in isolated


def test_mapping_store_and_audit_logger_are_thread_safe(tmp_path) -> None:
    store = MappingStore(str(tmp_path / "state.sqlite3"))
    audit = AuditLogger(str(tmp_path / "audit.jsonl"))

    def write(index: int) -> str:
        rec = store.upsert_mapping(
            session_id="sess",
            workspace_id="ws",
            scope="session",
            kind="pii",
            subtype="email",
            value="a@example.com",
            store_value=True,
            materialization_class="pii",
        )
        audit.log({"index": index, "handle_id": rec.handle_id})
        return rec.handle_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        handles = list(pool.map(write, range(64)))
    assert len(set(handles)) == 1
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 64
    assert {json.loads(line)["index"] for line in lines} == set(range(64))


def test_audit_log_rotates_with_private_bounded_backups(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(path), max_bytes=220, backup_count=2)
    for index in range(30):
        logger.log({"phase": "test", "sequence": index, "padding": "x" * 40})

    assert path.exists()
    assert path.with_name("audit.jsonl.1").exists()
    assert path.with_name("audit.jsonl.2").exists()
    assert not path.with_name("audit.jsonl.3").exists()
    for candidate in (path, path.with_name("audit.jsonl.1"), path.with_name("audit.jsonl.2")):
        assert candidate.stat().st_mode & 0o777 == 0o600
        assert candidate.stat().st_size <= 220


def test_admin_audit_reads_recent_rotated_files(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    cfg = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(path),
        audit_log_max_bytes=220,
        audit_log_backups=2,
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(api_key="provider-key"),
    )
    app = create_app(cfg, EmptyUpstream())
    with TestClient(app) as client:
        for index in range(30):
            app.state.admin_service.audit.log({
                "request_id": f"req_{index:012x}",
                "phase": "rotation_test",
                "padding": "x" * 40,
            })
        current_lines = path.read_text(encoding="utf-8").splitlines()
        response = client.get("/api/admin/audit?limit=100")

    assert response.status_code == 200
    events = [event for event in response.json()["events"] if event["phase"] == "rotation_test"]
    assert len(events) > len(current_lines)


def test_gc_tombstones_expired_mappings_in_every_scope(tmp_path) -> None:
    store = MappingStore(str(tmp_path / "state.sqlite3"))
    records = [
        store.upsert_mapping(
            session_id="sess",
            workspace_id="ws",
            scope=scope,
            kind="secret",
            subtype=f"token_{scope}",
            value=f"secret-{scope}",
            store_value=True,
            materialization_class="secret",
            ttl_seconds=-1,
        )
        for scope in ("request", "session", "workspace")
    ]
    assert store.tombstone_expired() == 3
    for record in records:
        current = store.get(record.handle_id)
        assert current is not None
        assert current.state == "tombstoned"
        assert current.value is None
