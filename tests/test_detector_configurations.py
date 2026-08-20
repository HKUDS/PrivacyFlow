from __future__ import annotations

import json
from pathlib import Path

from gateway.detector_control import DetectorControlPlane
from gateway.detectors.base import Detector
from gateway.detectors.findings import SourceBlock
from gateway.detectors.flow import DetectorFlow, FlowModule
from gateway.mapping_store import MappingStore
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import RedactionEngine


def control(tmp_path):
    applied = []
    instance = DetectorControlPlane(str(tmp_path / "detector-control.json"), applied.append)
    return instance, applied


def subtypes(manager, text: str) -> set[str]:
    return {finding.subtype for finding in manager.scan_findings(text)}


def test_fixed_builtin_comprehensive_pipeline_is_active_and_available(tmp_path) -> None:
    detector_control, applied = control(tmp_path)

    configuration = detector_control.active_configuration()
    assert configuration["id"] == "builtin.comprehensive"
    assert detector_control.active_configuration_available() is True
    assert len(applied) == 1

    module_ids = {module["id"] for module in configuration["modules"]}
    assert {"credentials", "personal_data", "local_paths"} <= module_ids


def test_builtin_comprehensive_detects_rules_paths_pii_and_secrets(tmp_path) -> None:
    detector_control, applied = control(tmp_path)
    manager = applied[0]
    fixture_dir = Path(__file__).parent / "fixtures"
    benign = (fixture_dir / "detector_shell_benign.txt").read_text(encoding="utf-8")
    sensitive = (fixture_dir / "detector_shell_sensitive.txt").read_text(encoding="utf-8")

    assert manager.scan_findings(benign) == []
    assert {"api_key", "access_url_token", "credential_username", "credential_password", "local_path"} == subtypes(manager, sensitive)

    text = "sk-proj-abcdefghijklmnopqrstuvwxyz123456 alice@example.com /Users/alice/private/project/.env"
    detected = subtypes(manager, text)
    assert {"api_key", "email", "local_path"} <= detected


def test_fixed_pipeline_has_no_local_model_references(tmp_path) -> None:
    detector_control, _ = control(tmp_path)

    assert detector_control.local_model_references() == []


def test_pf_enabled_persists_across_control_plane_reload(tmp_path) -> None:
    detector_control, _ = control(tmp_path)

    assert detector_control.pf_enabled() is True
    assert detector_control.set_pf_enabled(False) is False
    assert detector_control.pf_enabled() is False
    state = json.loads((tmp_path / "detector-control.json").read_text(encoding="utf-8"))
    assert state["pf_enabled"] is False

    reloaded, _ = control(tmp_path)
    assert reloaded.pf_enabled() is False
    assert reloaded.active_configuration()["id"] == "builtin.comprehensive"
    assert reloaded.active_configuration_available() is True


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
    detector_control, applied = control(tmp_path)
    manager = applied[0]

    assert detector_control.active_configuration()["core_guard_enabled"] is True
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


def test_corrupt_detector_state_does_not_block_fixed_pipeline_startup(tmp_path) -> None:
    (tmp_path / "detector-control.json").write_text("{not valid json", encoding="utf-8")

    detector_control, applied = control(tmp_path)

    assert detector_control.active_configuration()["id"] == "builtin.comprehensive"
    assert detector_control.active_configuration_available() is True
    assert len(applied) == 1
