from __future__ import annotations

from gateway.mapping_store import MappingStore
from gateway.models import MaterializationResult
from gateway.path_alias_manager import PathAliasManager
from gateway.placeholder_parser import ParsedPlaceholder, PlaceholderSigner
from gateway.policy_engine import PolicyEngine


class MaterializationEngine:
    def __init__(self, store: MappingStore, signer: PlaceholderSigner, policy: PolicyEngine, workspace_id: str = "default") -> None:
        self.store = store
        self.signer = signer
        self.policy = policy
        self.workspace_id = workspace_id
        self.path_aliases = PathAliasManager()

    def materialize_placeholder(self, ph: ParsedPlaceholder, *, session_id: str, sink_type: str) -> MaterializationResult:
        if not self.signer.is_valid(ph):
            return MaterializationResult(False, None, "APG_PLACEHOLDER_INVALID_MAC", False, "regenerate_context")
        ok, rec, code = self.store.validate_active(ph.handle_id, session_id, self.workspace_id)
        if not ok or rec is None:
            return MaterializationResult(False, None, code, False, "regenerate_context")
        decision = self.policy.can_materialize(rec.kind, sink_type, rec.materialization_class)
        if not decision.allowed:
            return MaterializationResult(False, None, decision.reason_code, decision.retryable, decision.next_action)
        if rec.value is None:
            return MaterializationResult(False, None, "APG_VALUE_UNAVAILABLE", False, "ask_user_for_approval")
        if rec.kind == "path" and ph.suffix:
            joined = self.path_aliases.join_suffix(rec.value, ph.suffix)
            if joined is None:
                return MaterializationResult(False, None, "APG_PATH_TRAVERSAL_BLOCKED", False, "regenerate_context")
            return MaterializationResult(True, joined)
        return MaterializationResult(True, rec.value)
