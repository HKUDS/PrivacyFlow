from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from gateway.detector_control import DetectorConfigurationConflict, DetectorControlError, DetectorControlPlane
from gateway.detector_manager import DetectorManager
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

    assert "api_key" in subtypes(credentials, text)
    assert "email" not in subtypes(credentials, text)
    assert "email" in subtypes(personal, text)
    assert "api_key" not in subtypes(personal, text)
    assert "local_path" in subtypes(local_context, text)
    assert "email" not in subtypes(local_context, text)
    assert {"api_key", "email", "local_path"} <= subtypes(comprehensive, text)
    path_config = detector_control.get_configuration("builtin.local_context")["modules"][0]["config"]
    assert detector_control.get_configuration("builtin.local_context")["modules"][0]["name"] == "本地路径"
    assert path_config["path_risk"] == "medium"
    assert "credential_names" not in path_config
    assert "credential_risk" not in path_config
    assert "path_action" not in path_config
    assert "credential_action" not in path_config

    diagnostics = comprehensive.diagnostics()
    assert [item["id"] for item in diagnostics] == ["pf_core", "credentials", "personal_data", "local_paths", "entropy", "personal_model"]
    assert diagnostics[-1]["status"] == "disabled"


def test_builtin_presets_are_precise_on_realistic_shell_fixtures(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    fixture_dir = Path(__file__).parent / "fixtures"
    benign = (fixture_dir / "detector_shell_benign.txt").read_text(encoding="utf-8")
    sensitive = (fixture_dir / "detector_shell_sensitive.txt").read_text(encoding="utf-8")

    assert detector_control.manager_for_configuration("builtin.comprehensive").scan_findings(benign) == []

    credentials = subtypes(detector_control.manager_for_configuration("builtin.credentials"), sensitive)
    personal = subtypes(detector_control.manager_for_configuration("builtin.personal"), sensitive)
    local_context = subtypes(detector_control.manager_for_configuration("builtin.local_context"), sensitive)
    comprehensive = subtypes(detector_control.manager_for_configuration("builtin.comprehensive"), sensitive)

    assert credentials == {"api_key", "access_url_token", "credential_password"}
    assert personal == {"credential_username"}
    assert local_context == {"local_path"}
    assert comprehensive == {
        "api_key",
        "access_url_token",
        "credential_username",
        "credential_password",
        "local_path",
    }
    credential_rules = next(
        module["config"]["rules"]
        for module in detector_control.get_configuration("builtin.credentials")["modules"]
        if module["type"] == "regex"
    )
    assert len(credential_rules) == 13
    assert not any("apg_test" in rule["id"] or rule["id"].endswith("_prefix") for rule in credential_rules)


def test_local_model_availability_requires_cached_model_when_downloads_are_disabled(tmp_path, monkeypatch) -> None:
    applied = []
    detector_control = DetectorControlPlane(
        {},
        str(tmp_path / "detector-control.json"),
        applied.append,
        model_path_resolver=lambda *_args: None,
    )
    monkeypatch.setattr(detector_control, "_module_available", lambda _package: True)
    module = next(
        item
        for item in detector_control.get_configuration("builtin.personal")["modules"]
        if item["type"] == "local_model"
    )
    assert module["runtime_available"] is False
    assert module["local_model_id"].startswith("lmodel_")

    detector_control.model_path_resolver = lambda *_args: str(tmp_path / "cached-model")
    module = next(
        item
        for item in detector_control.get_configuration("builtin.personal")["modules"]
        if item["type"] == "local_model"
    )
    assert module["runtime_available"] is True


def test_copy_edit_activate_and_atomic_revision(tmp_path) -> None:
    detector_control, applied = control(tmp_path)
    created = detector_control.create_configuration({"name": "Custom", "source_id": "builtin.credentials"})
    assert created["source_template_id"] == "builtin.credentials"
    created["modules"].reverse()
    created["modules"][0]["config"]["min_entropy"] = 4.2
    saved = detector_control.save_configuration(created["id"], created)
    assert [module["id"] for module in saved["modules"]] == ["entropy", "credentials"]
    assert saved["revision"] == 2

    with pytest.raises(DetectorConfigurationConflict) as conflict:
        detector_control.save_configuration(created["id"], created)
    assert conflict.value.code == "DETECTOR_REVISION_STALE"

    detector_control.activate_configuration(created["id"])
    assert detector_control.catalog()["active_configuration_id"] == created["id"]
    assert applied[-1].hierarchical.flow.preset == created["id"]
    with pytest.raises(DetectorConfigurationConflict) as conflict:
        detector_control.delete_configuration(created["id"])
    assert conflict.value.code == "DETECTOR_CONFIGURATION_IN_USE"


def test_template_module_switch_persists_and_hot_applies(tmp_path) -> None:
    detector_control, applied = control(tmp_path)
    configuration_id = "builtin.comprehensive"
    module_id = "entropy"
    assert detector_control.active_configuration()["id"] == configuration_id
    assert next(
        module for module in detector_control.active_configuration()["modules"] if module["id"] == module_id
    )["enabled"] is False

    applied_before = len(applied)
    updated = detector_control.set_template_module_enabled(configuration_id, module_id, True)
    assert updated["readonly"] is True
    assert next(module for module in updated["modules"] if module["id"] == module_id)["enabled"] is True
    assert len(applied) == applied_before + 1
    assert applied[-1].hierarchical.flow.preset == configuration_id

    state_path = tmp_path / "detector-control.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["template_module_overrides"] == {configuration_id: {module_id: True}}

    reloaded, _ = control(tmp_path)
    restored = reloaded.get_configuration(configuration_id)
    assert next(module for module in restored["modules"] if module["id"] == module_id)["enabled"] is True

    reset = reloaded.set_template_module_enabled(configuration_id, module_id, False)
    assert next(module for module in reset["modules"] if module["id"] == module_id)["enabled"] is False
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["template_module_overrides"] == {}

    custom = reloaded.create_configuration({"name": "Custom", "source_id": configuration_id})
    with pytest.raises(DetectorControlError, match="Only preset"):
        reloaded.set_template_module_enabled(custom["id"], module_id, True)
    with pytest.raises(DetectorControlError, match="boolean"):
        reloaded.set_template_module_enabled(configuration_id, module_id, "yes")  # type: ignore[arg-type]


def test_failed_hot_apply_restores_previous_manager_and_persisted_state(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    created = detector_control.create_configuration({"name": "Candidate", "source_id": "builtin.credentials"})
    path = tmp_path / "detector-control.json"
    before = path.read_bytes()
    previous_manager = detector_control._manager
    applied: list[DetectorManager] = []

    def fail_new_manager(manager: DetectorManager) -> None:
        applied.append(manager)
        if manager is not previous_manager:
            raise RuntimeError("injected apply failure")

    detector_control.apply_manager = fail_new_manager

    with pytest.raises(RuntimeError, match="injected apply failure"):
        detector_control.activate_configuration(created["id"])

    assert detector_control._manager is previous_manager
    assert detector_control.catalog()["active_configuration_id"] == "builtin.comprehensive"
    assert path.read_bytes() == before
    assert applied[-1] is previous_manager


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
                        "risk": "high",
                        "suggested_action": "redact",
                    }
                ]
            },
        }
    ]
    with pytest.raises(DetectorControlError, match="repeating groups"):
        detector_control.save_configuration(saved["id"], saved)


def test_custom_regex_uses_cancellable_engine_without_executor_thread(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    created = detector_control.create_configuration({"name": "Bounded regex"})
    created["modules"] = [{
        "id": "bounded_digits",
        "name": "Bounded digits",
        "type": "regex",
        "enabled": True,
        "timeout_ms": None,
        "failure_mode": "open",
        "config": {"rules": [{
            "id": "custom.bounded_digits",
            "pattern": "x" + r"\d{1,30}" * 20 + "Y",
            "type": "MACHINE_SECRET",
            "subtype": "bounded_digits",
            "risk": "high",
            "suggested_action": "redact",
        }]},
    }]
    saved = detector_control.save_configuration(created["id"], created)
    manager = detector_control.manager_for_configuration(saved["id"])
    module = next(item for item in manager.hierarchical.flow.modules if item.id == "bounded_digits")
    assert module.timeout_ms is None
    assert module.detector is not None
    assert module.detector.match_timeout_ms == 100  # type: ignore[attr-defined]

    started = time.perf_counter()
    assert manager.scan_findings("x" + "1" * 400 + "Z") == []
    assert time.perf_counter() - started < 1


def test_yaml_catastrophic_regex_times_out_without_leaking_worker_thread() -> None:
    manager = DetectorManager(detectors_config={"flow": {"id": "unsafe", "modules": [{
        "id": "unsafe",
        "type": "regex_rules",
        "fail_open": True,
        "rules": [{
            "id": "custom.unsafe",
            "pattern": "(a+)+$",
            "type": "MACHINE_SECRET",
            "subtype": "unsafe",
            "risk": "high",
            "suggested_action": "redact",
        }],
    }]}})
    started = time.perf_counter()
    assert manager.scan_findings("a" * 50_000 + "!") == []
    assert time.perf_counter() - started < 1
    diagnostic = manager.diagnostics()[0]
    assert diagnostic["status"] == "timeout"
    assert diagnostic["error"] == "module_timeout"


def test_invalid_stored_configuration_does_not_reset_other_state(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    valid = detector_control.create_configuration({"name": "Valid", "source_id": "builtin.credentials"})
    detector_control.activate_configuration(valid["id"])
    detector_control.set_pf_enabled(False)
    path = tmp_path / "detector-control.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["configurations"].append({"id": "broken"})
    path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.warns(RuntimeWarning, match="Ignoring invalid detector configuration"):
        reloaded, _ = control(tmp_path)
    assert reloaded.pf_enabled() is False
    assert reloaded.catalog()["active_configuration_id"] == valid["id"]
    assert [item["id"] for item in reloaded.catalog()["configurations"]] == [valid["id"]]
    reloaded.set_pf_enabled(True)
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["pf_enabled"] is True
    assert any(item.get("id") == "broken" for item in persisted["configurations"])
    assert valid["id"] in {item["id"] for item in persisted["configurations"]}


def test_deployment_template_modules_cannot_be_toggled(tmp_path) -> None:
    detector_control, _ = control(tmp_path, {"preset": "strict"})
    deployment = detector_control.get_configuration("deployment.current")
    with pytest.raises(DetectorControlError, match="built-in templates"):
        detector_control.set_template_module_enabled("deployment.current", deployment["modules"][0]["id"], False)


def test_missing_local_model_is_reported_as_unavailable() -> None:
    class MissingModel(Detector):
        name = "missing-model"

        def detect(self, block, normalized):
            raise OSError("cache path must not enter diagnostics")

    flow = DetectorFlow([FlowModule("local_pii", "local_model", MissingModel())])
    result = flow.scan_block(SourceBlock.from_text("alice@example.com"))
    assert result.diagnostics[0].status == "unavailable"
    assert result.diagnostics[0].error == "model_unavailable"


def test_core_guard_is_always_enabled_and_materialization_boundary_remains_strict(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    created = detector_control.create_configuration({"name": "Always guarded", "source_id": "builtin.local_context"})
    created["core_guard_enabled"] = False
    saved = detector_control.save_configuration(created["id"], created)
    manager = detector_control.manager_for_configuration(saved["id"])
    assert saved["core_guard_enabled"] is True
    assert manager.core_guard_enabled is True
    assert "signed_placeholder" in subtypes(manager, "<APG:v1:secret:fake:fake:123:fake>")

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
    assert events[0]["action"] == "preserve"
    assert events[0]["result_code"] != "OK"


def test_unsupported_detector_state_falls_back_to_safe_defaults(tmp_path) -> None:
    path = tmp_path / "detector-control.json"
    original = json.dumps({"version": 999, "preset": "future", "future_field": {"keep": True}}).encode()
    path.write_bytes(original)
    with pytest.warns(RuntimeWarning, match="Unsupported detector configuration state version"):
        detector_control, _ = control(tmp_path)
    assert detector_control.catalog()["active_configuration_id"] == "builtin.comprehensive"
    assert detector_control.catalog()["configurations"] == []

    detector_control.set_pf_enabled(False)
    backups = list(tmp_path.glob("detector-control.json.recovery-*.bak"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == original
    assert backups[0].stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text(encoding="utf-8"))["pf_enabled"] is False


def test_malformed_detector_state_is_preserved_before_first_write(tmp_path) -> None:
    path = tmp_path / "detector-control.json"
    original = b'{"version": 3, "configurations": ['
    path.write_bytes(original)
    detector_control, _ = control(tmp_path)

    detector_control.set_pf_enabled(False)

    backups = list(tmp_path.glob("detector-control.json.recovery-*.bak"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == original


def test_template_local_model_override_is_visible_in_references(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    detector_control.activate_configuration("builtin.comprehensive")
    before = next(
        item
        for item in detector_control.local_model_references()
        if item["module_id"] == "personal_model" and item["configuration_id"] == "builtin.comprehensive"
    )
    assert before["active"] is True
    assert before["enabled"] is False

    detector_control.set_template_module_enabled("builtin.comprehensive", "personal_model", True)
    after = next(
        item
        for item in detector_control.local_model_references()
        if item["module_id"] == "personal_model" and item["configuration_id"] == "builtin.comprehensive"
    )
    assert after["enabled"] is True
    assert next(
        module
        for module in detector_control.active_configuration()["modules"]
        if module["id"] == "personal_model"
    )["enabled"] is True


def test_incomplete_legacy_configuration_loads_with_defaults(tmp_path) -> None:
    path = tmp_path / "detector-control.json"
    path.write_text(
        json.dumps({
            "version": 3,
            "active_configuration_id": "dcfg_0123456789ab",
            "pf_enabled": False,
            "configurations": [{"id": "dcfg_0123456789ab", "name": "Legacy custom"}],
        }),
        encoding="utf-8",
    )
    detector_control, applied = control(tmp_path)
    assert detector_control.pf_enabled() is False
    assert detector_control.catalog()["active_configuration_id"] == "dcfg_0123456789ab"
    loaded = detector_control.get_configuration("dcfg_0123456789ab")
    assert loaded["name"] == "Legacy custom"
    assert loaded["modules"] == []
    assert loaded["flow_timeout_ms"] == 1500
    assert applied[-1].hierarchical.flow.flow_timeout_ms == 1500

    detector_control.set_pf_enabled(True)
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["pf_enabled"] is True
    assert persisted["active_configuration_id"] == "dcfg_0123456789ab"
    assert persisted["configurations"][0]["id"] == "dcfg_0123456789ab"


def test_null_flow_timeout_defaults_instead_of_disabling(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    created = detector_control.create_configuration({"name": "Timeout"})
    saved = detector_control.save_configuration(created["id"], {**created, "flow_timeout_ms": None})
    assert saved["flow_timeout_ms"] == 1500
    manager = detector_control.manager_for_configuration(created["id"])
    assert manager.hierarchical.flow.flow_timeout_ms == 1500


def test_invalid_deployment_module_is_retained_on_disk(tmp_path) -> None:
    path = tmp_path / "detector-control.json"
    broken = {
        "id": "dcfg_aaaaaaaaaaaa",
        "name": "Broken deploy",
        "modules": [{"id": "yaml_flow", "type": "deployment", "config": {}}],
    }
    path.write_text(
        json.dumps({
            "version": 3,
            "active_configuration_id": "dcfg_aaaaaaaaaaaa",
            "pf_enabled": True,
            "configurations": [broken],
        }),
        encoding="utf-8",
    )
    with pytest.warns(RuntimeWarning, match="Ignoring invalid detector configuration"):
        detector_control, _ = control(tmp_path)
    assert detector_control.catalog()["active_configuration_id"] == "builtin.comprehensive"
    assert detector_control.catalog()["configurations"] == []
    detector_control.set_pf_enabled(False)
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["pf_enabled"] is False
    assert persisted["configurations"] == [broken]


def test_runtime_module_rejects_deployment_without_runtime(tmp_path) -> None:
    detector_control, _ = control(tmp_path)
    with pytest.raises(DetectorControlError, match="require a runtime"):
        detector_control._runtime_module({
            "id": "yaml_flow",
            "type": "deployment",
            "enabled": True,
            "failure_mode": "closed",
            "config": {},
        })
