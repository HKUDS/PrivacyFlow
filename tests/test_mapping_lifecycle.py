from __future__ import annotations

import sqlite3
import time

import pytest

from gateway.mapping_store import MappingRetentionConflictError, MappingStore


def test_mapping_retention_is_disabled_by_default(components) -> None:
    store, _, _ = components
    policy = store.mapping_retention_policy("ws")
    assert policy.enabled is False
    assert policy.idle_ttl_seconds == 86_400

    record = store.upsert_mapping(
        session_id="sess",
        workspace_id="ws",
        scope="session",
        kind="secret",
        subtype="api_key",
        value="secret-value",
        store_value=True,
        materialization_class="secret",
    )
    assert record.idle_expires_at == 0
    assert record.max_expires_at == 0
    assert store.tombstone_expired() == 0
    assert store.validate_active(record.handle_id, "sess", "ws")[0] is True


def test_mapping_retention_policy_updates_existing_records_and_checks_revision(components) -> None:
    store, _, _ = components
    record = store.upsert_mapping(
        session_id="sess",
        workspace_id="ws",
        scope="session",
        kind="secret",
        subtype="api_key",
        value="secret-value",
        store_value=True,
        materialization_class="secret",
    )
    enabled = store.set_mapping_retention_policy(
        workspace_id="ws",
        enabled=True,
        idle_ttl_seconds=3600,
        expected_revision=0,
    )
    assert enabled.enabled is True
    assert enabled.revision == 1
    expiring = store.get(record.handle_id)
    assert expiring is not None
    assert expiring.idle_expires_at > int(time.time())
    assert expiring.max_expires_at == 0

    with pytest.raises(MappingRetentionConflictError):
        store.set_mapping_retention_policy(
            workspace_id="ws",
            enabled=False,
            idle_ttl_seconds=3600,
            expected_revision=0,
        )

    disabled = store.set_mapping_retention_policy(
        workspace_id="ws",
        enabled=False,
        idle_ttl_seconds=3600,
        expected_revision=1,
    )
    assert disabled.enabled is False
    retained = store.get(record.handle_id)
    assert retained is not None
    assert retained.idle_expires_at == 0
    assert retained.max_expires_at == 0


def test_history_cleanup_removes_only_old_audit_rows_and_tombstones(tmp_path) -> None:
    store = MappingStore(str(tmp_path / "state.sqlite3"), namespace="PF")
    old = store.upsert_mapping(
        session_id="old-session",
        workspace_id="ws",
        scope="session",
        kind="secret",
        subtype="api_key",
        value="old-secret",
        store_value=True,
        materialization_class="secret",
    )
    recent = store.upsert_mapping(
        session_id="recent-session",
        workspace_id="ws",
        scope="session",
        kind="secret",
        subtype="api_key",
        value="recent-secret",
        store_value=True,
        materialization_class="secret",
    )
    store.tombstone(old.handle_id)
    store.tombstone(recent.handle_id)
    with store.conn:
        store.conn.execute("UPDATE mappings SET last_seen_at=1 WHERE handle_id=?", (old.handle_id,))
    operation = {
        "direction": "replacement",
        "handle_id": "secr_history",
        "kind": "secret",
        "subtype": "api_key",
        "risk": "high",
        "detector": "test",
        "action": "redact",
        "sink": "upstream",
        "result_code": "OK",
    }
    store.record_audit_operations(
        request_id="req_old",
        session_id="sess",
        workspace_id="ws",
        endpoint="/v1/responses",
        timestamp=1,
        operations=[operation],
    )
    store.record_audit_operations(
        request_id="req_recent",
        session_id="sess",
        workspace_id="ws",
        endpoint="/v1/responses",
        timestamp=100,
        operations=[{**operation, "handle_id": "secr_recent"}],
    )

    removed = store.purge_history(50)

    assert removed["mapping_tombstones"] == 1
    assert removed["audit_operations"] == 1
    assert store.get(old.handle_id) is None
    assert store.get(recent.handle_id) is not None
    assert store.audit_operations_for_request("req_old", "ws") == []
    assert len(store.audit_operations_for_request("req_recent", "ws")) == 1


def test_unsupported_mapping_database_schema_is_rejected(tmp_path) -> None:
    database = tmp_path / "old.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE mappings (
              handle_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, workspace_id TEXT NOT NULL,
              scope TEXT NOT NULL, kind TEXT NOT NULL, subtype TEXT NOT NULL, value TEXT,
              fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
              idle_expires_at INTEGER NOT NULL, max_expires_at INTEGER NOT NULL, state TEXT NOT NULL,
              policy_hash TEXT NOT NULL, materialization_class TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO mappings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("secr_old", "sess", "ws", "session", "secret", "api_key", "secret-value", "fp", 1, 1, 2, 3, "active", "default", "secret"),
        )
    with pytest.raises(RuntimeError, match="Unsupported APG mapping database schema"):
        MappingStore(str(database))


def test_request_scoped_mapping_expires(components) -> None:
    store, _, _ = components
    rec = store.upsert_mapping(session_id="sess", workspace_id="ws", scope="request", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii", ttl_seconds=0)
    time.sleep(1)
    ok, _, code = store.validate_active(rec.handle_id, "sess", "ws")
    assert not ok
    assert code == "APG_PLACEHOLDER_EXPIRED"


def test_session_pseudonym_stable_within_ttl(components) -> None:
    store, _, _ = components
    a = store.upsert_mapping(session_id="sess", workspace_id="ws", scope="session", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii")
    b = store.upsert_mapping(session_id="sess", workspace_id="ws", scope="session", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii")
    assert a.handle_id == b.handle_id


def test_expired_placeholder_returns_unresolved_not_guessed(components) -> None:
    store, _, _ = components
    rec = store.upsert_mapping(session_id="sess", workspace_id="ws", scope="request", kind="path", subtype="local_path", value="/tmp/a", store_value=True, materialization_class="path", ttl_seconds=0)
    time.sleep(1)
    ok, _, code = store.validate_active(rec.handle_id, "sess", "ws")
    assert not ok
    assert code == "APG_PLACEHOLDER_EXPIRED"


def test_tombstone_error_retryable_false(components) -> None:
    from gateway.materialization_engine import MaterializationEngine

    store, signer, policy = components
    rec = store.upsert_mapping(session_id="sess", workspace_id="ws", scope="request", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii")
    store.tombstone(rec.handle_id)
    ph = signer.parse(signer.issue("pii", rec.handle_id, "sess"))[0]
    result = MaterializationEngine(store, signer, policy, "ws").materialize_placeholder(ph, session_id="sess", sink_type="local_user")
    assert result.error_code == "APG_PLACEHOLDER_TOMBSTONED"
    assert result.retryable is False



def test_repeated_sightings_refresh_idle_not_beyond_max(components) -> None:
    store, _, _ = components
    rec = store.upsert_mapping(session_id="sess", workspace_id="ws", scope="session", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii", ttl_seconds=1, max_ttl_seconds=2)
    first_max = rec.max_expires_at
    time.sleep(1)
    store.validate_active(rec.handle_id, "sess", "ws")
    refreshed = store.get(rec.handle_id)
    assert refreshed.max_expires_at == first_max
    assert refreshed.idle_expires_at <= first_max
