from __future__ import annotations

from gateway.models import Detection, PolicyDecision


VALID_PII_MODES = {"pseudonymize", "redact", "allow"}


class PolicyEngine:
    """Decides what action a detection triggers and what sinks may materialize
    a stored mapping back to its raw value.

    ``pii_mode`` is the disposition selector for PII detections, controlled by
    configuration (``APG_PII_MODE`` env / ``pii_mode`` YAML):

    - ``pseudonymize`` (default): emit ``<APG_PII:handle>`` so the human-path
      mapping can be restored to user-visible local text.
    - ``redact``: treat PII like a regular secret — emit a signed
      ``<APG:v1:secret:...>`` placeholder and gate materialization.
    - ``allow``: pass PII through unchanged (DEVELOPMENT ONLY; equivalent to
      disabling redaction for PII; never use with ``strict_mode=True``).
    """

    def __init__(self, pii_mode: str = "pseudonymize") -> None:
        if pii_mode not in VALID_PII_MODES:
            raise ValueError(f"Invalid pii_mode '{pii_mode}'. Must be one of: {', '.join(sorted(VALID_PII_MODES))}")
        self.pii_mode = pii_mode

    def decision_for_detection(self, detection: Detection) -> PolicyDecision:
        if detection.type == "secret":
            return PolicyDecision(True, "redact", f"redact_{detection.subtype}", retryable=False)
        if detection.type == "pii":
            if self.pii_mode == "allow":
                return PolicyDecision(False, "allow", "pii_allow_passthrough", retryable=False)
            if self.pii_mode == "redact":
                return PolicyDecision(True, "redact", f"redact_pii_{detection.subtype}", retryable=False)
            return PolicyDecision(True, "pseudonymize", f"pseudonymize_{detection.subtype}", retryable=False)
        if detection.type == "path":
            return PolicyDecision(True, "alias", "alias_local_path", retryable=False)
        return PolicyDecision(True, "redact", f"redact_unknown_{detection.subtype}", retryable=False)

    def can_materialize(self, kind: str, sink_type: str, materialization_class: str) -> PolicyDecision:
        # Iron rule: secrets and (in redact mode) PII are only ever
        # materialized into local tool-call argument fields. The remote LLM
        # and any other sink never see raw secret values. Whether a tool
        # should actually run, which domain it may call, and whether the user
        # must approve, are the agent harness' responsibility — APG does not
        # police tool usage.
        if materialization_class == "none":
            return PolicyDecision(False, "block", "non_materializable", retryable=False)
        if sink_type == "remote_llm":
            return PolicyDecision(False, "block", "remote_materialization_blocked", retryable=False)
        if kind == "secret":
            if sink_type == "local_tool":
                return PolicyDecision(True, "allow", "secret_local_tool_materialization_allowed")
            return PolicyDecision(False, "block", "secret_not_local_tool", "Secrets are only materialized into local tool-call arguments.", False, "use_local_tool_call")
        if kind in {"pii", "path"}:
            if sink_type in {"local_tool", "local_user"}:
                return PolicyDecision(True, "allow", "materialization_allowed")
            return PolicyDecision(False, "block", "materialization_blocked", retryable=False)
        return PolicyDecision(True, "allow", "materialization_allowed")