from __future__ import annotations

import time


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


def test_gc_does_not_remove_active_session_scoped_mapping(components) -> None:
    store, _, _ = components
    rec = store.upsert_mapping(session_id="sess", workspace_id="ws", scope="session", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii")
    store.expire_request_scope()
    assert store.get(rec.handle_id).state == "active"


def test_repeated_sightings_refresh_idle_not_beyond_max(components) -> None:
    store, _, _ = components
    rec = store.upsert_mapping(session_id="sess", workspace_id="ws", scope="session", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii", ttl_seconds=1, max_ttl_seconds=2)
    first_max = rec.max_expires_at
    time.sleep(1)
    store.validate_active(rec.handle_id, "sess", "ws")
    refreshed = store.get(rec.handle_id)
    assert refreshed.max_expires_at == first_max
    assert refreshed.idle_expires_at <= first_max
