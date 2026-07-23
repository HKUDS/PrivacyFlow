from __future__ import annotations

import json
import os

import pytest

from gateway.detector_control import DetectorConfigurationConflict, DetectorControlError, DetectorControlPlane
from gateway.detectors.base import Detector
from gateway.detectors.findings import SourceBlock
from gateway.detectors.flow import DetectorFlow, FlowModule
from gateway.mapping_store import MappingStore
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import RedactionEngine


def control(tmp_path, base_config=None):
    applied = []
    instance = DetectorControlPlane(base_config or {}, str(tmp_path / "detector-control.json"), applied.append)
    return instance, applied


def subtypes(manager, text: str) -> set[str]:
    return {finding.subtype for finding in manager.scan_findings(text)}


def test_content_templates_detect_declared_categories(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    credentials = detector_control.manager_for_configuration("builtin.credentials")
    personal = detector_control.manager_for_configuration("builtin.personal")
    local_context = detector_control.manager_for_configuration("builtin.local_context")
    comprehensive = detector_control.manager_for_configuration("builtin.comprehensive")
    text = "sk-proj-abcdefghijklmnopqrstuvwxyz123456 alice@example.com /Users/alice/private/project/.env"

    assert "openai_api_key" in subtypes(credentials, text)
    assert "email" not in subtypes(credentials, text)
    assert "email" in subtypes(personal, text)
    assert "openai_api_key" not in subtypes(personal, text)
    assert "credential_file" in subtypes(local_context, text)
    assert "email" not in subtypes(local_context, text)
    assert {"openai_api_key", "email", "credential_file"} <= subtypes(comprehensive, text)

    diagnostics = comprehensive.diagnostics()
    assert [item["id"] for item in diagnostics] == ["apg_core", "credentials", "personal_data", "local_paths", "entropy", "personal_model"]
    assert diagnostics[-1]["status"] == "disabled"


def test_copy_edit_activate_and_atomic_revision(tmp_path) -> None:
    detector_control, applied = control(tmp_path)
    created = detector_control.create_configuration({"name": "Custom", "source_id": "builtin.credentials"})
    assert created["source_template_id"] == "builtin.credentials"
    created["modules"].reverse()
    created["modules"][0]["config"]["min_entropy"] = 4.2
    saved = detector_control.save_configuration(created["id"], created)
    assert [module["id"] for module in saved["modules"]] == ["entropy", "credentials"]
    assert saved["revision"] == 2

    with pytest.raises(DetectorConfigurationConflict):
        detector_control.save_configuration(created["id"], created)

    detector_control.activate_configuration(created["id"])
    assert detector_control.catalog()["active_configuration_id"] == created["id"]
    assert applied[-1].hierarchical.flow.preset == created["id"]
    with pytest.raises(DetectorConfigurationConflict):
        detector_control.delete_configuration(created["id"])


def test_regex_validation_and_model_url_normalization(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    created = detector_control.create_configuration({"name": "Blank"})
    created["modules"] = [
        {
            "id": "model_pii",
            "name": "PII model",
            "type": "local_model",
            "enabled": False,
            "timeout_ms": 800,
            "failure_mode": "open",
            "config": {
                "adapter": "gliner",
                "model_name": "https://huggingface.co/nvidia/gliner-PII/tree/main",
                "threshold": 0.5,
                "device": "cpu",
                "aggregation_strategy": "simple",
                "labels": ["email"],
            },
        }
    ]
    saved = detector_control.save_configuration(created["id"], created)
    assert saved["modules"][0]["config"]["model_name"] == "nvidia/gliner-PII"

    saved["modules"] = [
        {
            "id": "unsafe_rules",
            "name": "Unsafe",
            "type": "regex",
            "enabled": True,
            "timeout_ms": 100,
            "failure_mode": "closed",
            "config": {
                "rules": [
                    {
                        "id": "custom.unsafe",
                        "pattern": "(a+)+$",
                        "type": "MACHINE_SECRET",
                        "subtype": "unsafe",
                        "confidence": 0.9,
                        "risk": "high",
                        "suggested_action": "redact",
                    }
                ]
            },
        }
    ]
    with pytest.raises(DetectorControlError, match="repeating groups"):
        detector_control.save_configuration(saved["id"], saved)


def test_missing_local_model_is_reported_as_unavailable() -> None:
    class MissingModel(Detector):
        name = "missing-model"

        def detect(self, block, normalized):
            raise OSError("cache path must not enter diagnostics")

    flow = DetectorFlow([FlowModule("local_pii", "local_model", MissingModel())])
    result = flow.scan_block(SourceBlock.from_text("alice@example.com"))
    assert result.diagnostics[0].status == "unavailable"
    assert result.diagnostics[0].error == "model_unavailable"


def test_core_guard_can_be_disabled_without_changing_materialization_boundary(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    created = detector_control.create_configuration({"name": "Unsafe", "source_id": "builtin.local_context"})
    created["core_guard_enabled"] = False
    saved = detector_control.save_configuration(created["id"], created)
    manager = detector_control.manager_for_configuration(saved["id"])
    assert manager.core_guard_enabled is False
    assert "signed_placeholder" not in subtypes(manager, "<APG:v1:secret:fake:fake:123:fake>")

    redactor = RedactionEngine(
        manager,
        MappingStore(str(tmp_path / "state.sqlite3")),
        PlaceholderSigner("secret", "ws"),
        PolicyEngine(),
        "ws",
    )
    forged = "<APG:v1:secret:secr_bogus:sess_bogus:1:AAAAAAAAAAAAAAAAAAAA>"
    value, events = redactor.materialize_local_text_with_events(forged, "sess_local")
    assert value == forged
    assert events[-1]["action"] == "preserve"
    assert events[-1]["result_code"] != "OK"


def test_v1_state_migrates_module_overrides_and_custom_rules(tmp_path) -> None:
    state_path = tmp_path / "detector-control.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "preset": None,
                "module_overrides": {"entropy": {"enabled": False}},
                "custom_rules": [
                    {
                        "id": "custom.partner",
                        "pattern": r"\bpartner_[A-Za-z0-9]{8,}\b",
                        "type": "MACHINE_SECRET",
                        "subtype": "partner",
                        "confidence": 0.9,
                        "risk": "high",
                        "suggested_action": "redact",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(state_path, 0o600)

    detector_control, _ = control(tmp_path)
    active = detector_control.active_configuration()
    assert active["id"] == "dcfg_6d69677261746564"
    assert next(module for module in active["modules"] if module["id"] == "entropy")["enabled"] is False
    assert any(
        rule["id"] == "custom.partner"
        for module in active["modules"]
        if module["type"] == "regex"
        for rule in module["config"]["rules"]
    )
    assert json.loads(state_path.read_text(encoding="utf-8"))["version"] == 2
    backup = tmp_path / "detector-control.json.apg.bak"
    assert backup.exists()
    assert os.stat(backup).st_mode & 0o777 == 0o600


def test_v2_copied_template_upgrades_historical_builtin_rule_without_losing_active_state(tmp_path) -> None:
    historical_pattern = (
        r"^\s*[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIAL|PRIVATE_KEY|DATABASE_URL)"
        r"[A-Z0-9_]*\s*=\s*(?P<value>.+)$"
    )
    detector_control, _ = control(tmp_path)
    created = detector_control.create_configuration({"name": "No entropy", "source_id": "builtin.comprehensive"})
    next(module for module in created["modules"] if module["id"] == "entropy")["enabled"] = False
    saved = detector_control.save_configuration(created["id"], created)
    detector_control.activate_configuration(saved["id"])

    state_path = tmp_path / "detector-control.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    active = next(item for item in state["configurations"] if item["id"] == saved["id"])
    env_rule = next(
        rule
        for module in active["modules"]
        if module["type"] == "regex"
        for rule in module["config"]["rules"]
        if rule["id"] == "secret.env_assignment"
    )
    env_rule["pattern"] = historical_pattern
    state_path.write_text(json.dumps(state), encoding="utf-8")

    reloaded, _ = control(tmp_path)
    restored = reloaded.active_configuration()
    assert restored["id"] == saved["id"]
    assert next(module for module in restored["modules"] if module["id"] == "entropy")["enabled"] is False
    assert "env_assignment" in subtypes(
        reloaded.manager_for_configuration(restored["id"]),
        '    42\u2192export SERVICE_TOKEN="secret-value"',
    )


def test_v1_migration_failure_keeps_original_state_and_runtime(tmp_path) -> None:
    state_path = tmp_path / "detector-control.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "custom_rules": [
                    {
                        "id": "custom.legacy",
                        "pattern": "(a+)+$",
                        "type": "MACHINE_SECRET",
                        "subtype": "legacy",
                        "confidence": 0.9,
                        "risk": "high",
                        "suggested_action": "redact",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(state_path, 0o600)

    detector_control, _ = control(tmp_path)
    active = detector_control.active_configuration()
    assert active["content_tags"] == ["legacy", "fallback"]
    assert json.loads(state_path.read_text(encoding="utf-8"))["version"] == 1
    assert not (tmp_path / "detector-control.json.apg.bak").exists()
    assert "legacy" in subtypes(detector_control.manager_for_configuration(active["id"]), "aaaa")
