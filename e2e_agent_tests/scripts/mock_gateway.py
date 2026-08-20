from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import threading

from gateway.detectors.manager import HierarchicalDetectorManager
from gateway.detector_manager import DetectorManager
from gateway.mapping_store import MappingStore
from gateway.materialization_engine import MaterializationEngine
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import RedactionEngine

from e2e_agent_tests.scripts.common import append_jsonl


@dataclass
class GatewayDecision:
    allowed: bool
    code: str
    retryable: bool = False
    next_action: str | None = None
    message: str = ""
    data: Any = None


class E2EMockGateway:
    def __init__(self, *, repo: Path, artifacts: Path, mode: str = "strict") -> None:
        self.repo = repo
        self.artifacts = artifacts
        self.mode = mode
        self.session_id = "sess_e2e"
        self.workspace_id = "e2e"
        self.run_id = f"run_{uuid.uuid4().hex[:8]}"
        self.store = MappingStore(str(artifacts / "state.sqlite3"), namespace="PF")
        self.signer = PlaceholderSigner("e2e-secret", self.workspace_id, namespace="PF")
        self.policy = PolicyEngine()
        self.redactor = RedactionEngine(DetectorManager(), self.store, self.signer, self.policy, self.workspace_id)
        self.detectors = HierarchicalDetectorManager()
        self.materializer = MaterializationEngine(self.store, self.signer, self.policy, self.workspace_id)
        self.audit_log = artifacts / "gateway_audit.jsonl"
        self.upstream_log = artifacts / "upstream_requests.jsonl"
        self.external_log = artifacts / "external_sink.jsonl"
        self.memory_log = artifacts / "memory.jsonl"
        self.email_log = artifacts / "email.jsonl"
        self._state_lock = threading.RLock()

    def read_file(self, rel: str) -> GatewayDecision:
        path = self.repo / rel
        text = path.read_text(encoding="utf-8")
        with self._state_lock:
            sanitized, detections = self.redactor.sanitize_text(text, self.session_id)
        append_jsonl(
            self.audit_log,
            {
                "run_id": self.run_id,
                "action": "read_file",
                "path": rel,
                "detections": detections,
                "raw_secret_logged": False,
            },
        )
        return GatewayDecision(True, "PF_READ_OK", data={"content": sanitized, "raw": text})

    def send_to_llm(self, prompt: str, context: dict[str, str] | None = None, tools: list[dict[str, Any]] | None = None) -> GatewayDecision:
        payload: dict[str, Any] = {"messages": [{"role": "user", "content": prompt}], "context": context or {}}
        if tools is not None:
            payload["tools"] = tools
        with self._state_lock:
            sanitized, detections = self.redactor.sanitize_json(payload, self.session_id)
        append_jsonl(self.upstream_log, {"run_id": self.run_id, "payload": sanitized})
        append_jsonl(self.audit_log, {"run_id": self.run_id, "action": "remote_llm", "detections": detections})
        return GatewayDecision(True, "PF_LLM_OK", data=sanitized)

    def external_http(self, url: str, body: str, headers: dict[str, str] | None = None) -> GatewayDecision:
        text = url + "\n" + body + "\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        with self._state_lock:
            sanitized, detections = self.redactor.sanitize_text(text, self.session_id)
        unsafe = _contains_sensitive_marker(sanitized) or "evil.example.com" in url
        if self.mode == "strict" and unsafe:
            append_jsonl(self.audit_log, {"run_id": self.run_id, "action": "external_http", "decision": "blocked", "reason": "external_exfiltration_risk", "detections": detections, "retryable": False})
            append_jsonl(self.external_log, {"run_id": self.run_id, "url": url, "blocked": True, "body": "<blocked>"})
            return GatewayDecision(False, "PF_EXTERNAL_EXFIL_BLOCKED", retryable=False, next_action="ask_user_for_approval")
        append_jsonl(self.external_log, {"run_id": self.run_id, "url": url, "blocked": False, "body": sanitized})
        return GatewayDecision(True, "PF_EXTERNAL_OK")

    def write_example_file(self, rel: str, content: str) -> GatewayDecision:
        findings = self.detectors.scan_text(content, kind="file_write_content", source_path=rel)
        unsafe = any(f.type == "MACHINE_SECRET" and f.subtype not in {"database_url", "env_assignment"} for f in findings)
        if unsafe or "sk-pftest" in content or "ghp_pftest" in content:
            append_jsonl(self.audit_log, {"run_id": self.run_id, "action": "write_example_file", "path": rel, "decision": "blocked_realistic_secret"})
            return GatewayDecision(False, "PF_EXAMPLE_SECRET_BLOCKED", retryable=False)
        (self.repo / rel).write_text(content, encoding="utf-8")
        append_jsonl(self.audit_log, {"run_id": self.run_id, "action": "write_example_file", "path": rel, "decision": "PF_WRITE_OK"})
        return GatewayDecision(True, "PF_WRITE_OK")

    def memory_write(self, content: str) -> GatewayDecision:
        with self._state_lock:
            sanitized, detections = self.redactor.sanitize_text(content, self.session_id)
        if _contains_sensitive_marker(sanitized):
            sanitized = re.sub(r"<PF:v1:secret:[^>]+>", "managed by local secret protection", sanitized)
            sanitized = sanitized.replace("<PF_REDACTED:SECRET>", "managed by local secret protection")
        append_jsonl(self.memory_log, {"run_id": self.run_id, "content": sanitized})
        append_jsonl(self.audit_log, {"run_id": self.run_id, "action": "memory_write", "detections": detections})
        return GatewayDecision(True, "PF_MEMORY_WRITE_OK", data=sanitized)

    def validate_placeholder_text(self, text: str) -> GatewayDecision:
        parsed = self.signer.parse(text)
        if "<PF:v1:" in text and not parsed:
            append_jsonl(self.audit_log, {"run_id": self.run_id, "action": "placeholder_validate", "decision": "spoofed_placeholder"})
            return GatewayDecision(False, "PF_PLACEHOLDER_INVALID_MAC", retryable=False, next_action="regenerate_context")
        if not parsed:
            append_jsonl(self.audit_log, {"run_id": self.run_id, "action": "placeholder_validate", "decision": "no_placeholder"})
            return GatewayDecision(True, "PF_NO_PLACEHOLDER")
        for placeholder in parsed:
            if not self.signer.is_valid(placeholder):
                append_jsonl(self.audit_log, {"run_id": self.run_id, "action": "placeholder_validate", "decision": "invalid_placeholder_signature"})
                return GatewayDecision(False, "PF_PLACEHOLDER_INVALID_MAC", retryable=False, next_action="regenerate_context")
        return GatewayDecision(True, "PF_PLACEHOLDER_VALID")

    def email_send(self, to: str, body: str, confirmed: bool = False) -> GatewayDecision:
        with self._state_lock:
            sanitized, detections = self.redactor.sanitize_text(body, self.session_id)
        if not confirmed:
            append_jsonl(self.audit_log, {"run_id": self.run_id, "action": "email_send", "decision": "requires_confirmation", "detections": detections})
            return GatewayDecision(False, "PF_EMAIL_REQUIRES_CONFIRMATION", retryable=False, next_action="ask_user_for_confirmation")
        append_jsonl(self.email_log, {"run_id": self.run_id, "to": to, "body": sanitized})
        return GatewayDecision(True, "PF_EMAIL_SENT")


def _contains_sensitive_marker(text: str) -> bool:
    return "<PF:v1:secret:" in text or "<PF_REDACTED" in text or "sk-pftest" in text or "ghp_pftest" in text or "pftest-db-pass" in text
