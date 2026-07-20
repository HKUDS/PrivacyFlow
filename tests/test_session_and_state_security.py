from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from gateway.audit_logger import AuditLogger
from gateway.config import GatewayConfig
from gateway.detector_manager import DetectorManager
from gateway.mapping_store import MappingStore
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import RedactionEngine
from gateway.server import create_app
from gateway.state.session_manager import SessionManager, SessionScopeError


class EmptyUpstream:
    async def request_json(self, method, path, payload=None):
        return 200, {"content-type": "application/json"}, {"choices": [{"message": {"content": "ok"}}]}


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
