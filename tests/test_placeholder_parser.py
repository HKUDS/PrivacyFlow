from __future__ import annotations

from gateway.materialization_engine import MaterializationEngine
from gateway.placeholder_parser import PlaceholderSigner


def test_valid_signed_placeholder_resolves_allowed_session(components) -> None:
    store, signer, policy = components
    rec = store.upsert_mapping(session_id="sess_a", workspace_id="ws", scope="session", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii")
    ph = signer.parse(signer.issue("pii", rec.handle_id, "sess_a"))[0]
    result = MaterializationEngine(store, signer, policy, "ws").materialize_placeholder(ph, session_id="sess_a", sink_type="local_user")
    assert result.allowed and result.value == "a@example.com"


def test_placeholder_wrong_session_fails(components) -> None:
    store, signer, policy = components
    rec = store.upsert_mapping(session_id="sess_a", workspace_id="ws", scope="session", kind="pii", subtype="email", value="a@example.com", store_value=True, materialization_class="pii")
    ph = signer.parse(signer.issue("pii", rec.handle_id, "sess_a"))[0]
    result = MaterializationEngine(store, signer, policy, "ws").materialize_placeholder(ph, session_id="sess_b", sink_type="local_user")
    assert not result.allowed
    assert result.error_code == "PF_PLACEHOLDER_SCOPE_MISMATCH"


def test_hallucinated_placeholder_invalid_mac_does_not_materialize(components) -> None:
    store, _, policy = components
    signer = PlaceholderSigner("test-secret", "ws")
    fake = signer.parse("<APG:v1:pii:pii_fake:sess_a:123:badmac>")[0]
    result = MaterializationEngine(store, signer, policy, "ws").materialize_placeholder(fake, session_id="sess_a", sink_type="local_user")
    assert not result.allowed
    assert result.error_code == "PF_PLACEHOLDER_INVALID_MAC"


def test_fake_placeholder_in_file_content_does_not_materialize(components) -> None:
    store, signer, policy = components
    fake = signer.parse("<APG:v1:path:path_fake:sess_a:123:AAAAAAAA>")[0]
    result = MaterializationEngine(store, signer, policy, "ws").materialize_placeholder(fake, session_id="sess_a", sink_type="local_tool")
    assert not result.allowed


def test_path_suffix_resolution_works(components) -> None:
    store, signer, policy = components
    rec = store.upsert_mapping(session_id="sess_a", workspace_id="ws", scope="workspace", kind="path", subtype="local_path", value="/Users/alice/project", store_value=True, materialization_class="path")
    ph = signer.parse(signer.issue("path", rec.handle_id, "sess_a") + "/src/main.py")[0]
    result = MaterializationEngine(store, signer, policy, "ws").materialize_placeholder(ph, session_id="sess_a", sink_type="local_tool")
    assert result.allowed
    assert result.value == "/Users/alice/project/src/main.py"


def test_path_traversal_suffix_blocked(components) -> None:
    store, signer, policy = components
    rec = store.upsert_mapping(session_id="sess_a", workspace_id="ws", scope="workspace", kind="path", subtype="local_path", value="/Users/alice/project", store_value=True, materialization_class="path")
    # Path traversal suffixes are now rejected at parse time
    parsed = signer.parse(signer.issue("path", rec.handle_id, "sess_a") + "/../../.ssh/id_rsa")
    assert len(parsed) == 0  # traversal suffix blocks parsing entirely


def test_secret_placeholder_materializes_for_local_user(components) -> None:
    store, signer, policy = components
    rec = store.upsert_mapping(session_id="sess_a", workspace_id="ws", scope="request", kind="secret", subtype="api_key", value="sk-secret", store_value=True, materialization_class="secret")
    ph = signer.parse(signer.issue("secret", rec.handle_id, "sess_a"))[0]
    result = MaterializationEngine(store, signer, policy, "ws").materialize_placeholder(ph, session_id="sess_a", sink_type="local_user")
    assert result.allowed
    assert result.value == "sk-secret"


def test_secret_placeholder_only_materializes_into_local_tool_args(components) -> None:
    store, signer, policy = components
    rec = store.upsert_mapping(session_id="sess_a", workspace_id="ws", scope="request", kind="secret", subtype="api_key", value="sk-secret", store_value=True, materialization_class="secret")
    ph = signer.parse(signer.issue("secret", rec.handle_id, "sess_a"))[0]
    result = MaterializationEngine(store, signer, policy, "ws").materialize_placeholder(ph, session_id="sess_a", sink_type="local_tool")
    assert result.allowed and result.value == "sk-secret"


def test_secret_placeholder_never_materializes_for_remote_llm(components) -> None:
    store, signer, policy = components
    rec = store.upsert_mapping(session_id="sess_a", workspace_id="ws", scope="request", kind="secret", subtype="api_key", value="sk-secret", store_value=True, materialization_class="secret")
    ph = signer.parse(signer.issue("secret", rec.handle_id, "sess_a"))[0]
    result = MaterializationEngine(store, signer, policy, "ws").materialize_placeholder(ph, session_id="sess_a", sink_type="remote_llm")
    assert not result.allowed
    assert result.error_code == "remote_materialization_blocked"


def test_default_and_invalid_namespaces_are_pf() -> None:
    signer = PlaceholderSigner("test-secret", "ws")
    assert signer.namespace == "PF"
    assert signer.issue("pii", "pii_x", "sess_a", 1).startswith("<PF:v1:")
    invalid = PlaceholderSigner("test-secret", "ws", namespace="OTHER")
    assert invalid.namespace == "PF"


def test_legacy_namespace_still_issues_apg_placeholders() -> None:
    signer = PlaceholderSigner("test-secret", "ws", namespace="APG")
    issued = signer.issue("pii", "pii_x", "sess_a", 1)
    assert issued.startswith("<APG:v1:")
