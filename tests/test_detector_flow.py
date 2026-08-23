from __future__ import annotations

import sys
import time
import types
from collections.abc import Iterable

from gateway.detectors.base import Detector
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.flow import (
    NORMALIZATION_CHUNK_SIZE,
    DetectorFlow,
    FlowModule,
    build_detector_flow,
    compile_flow_config,
)
from gateway.detectors.manager import HierarchicalDetectorManager
from gateway.detectors.normalizer import NormalizedText


def test_builtin_presets_compile() -> None:
    for preset in ("default", "fast", "model_enhanced", "strict"):
        compiled = compile_flow_config({"preset": preset})
        assert compiled["preset"] == preset
        assert compiled["modules"]


def test_custom_preset_from_zero_detects_rule() -> None:
    manager = HierarchicalDetectorManager(
        detectors_config={
            "preset": "custom_minimal",
            "presets": {
                "custom_minimal": {
                    "modules": [
                        {
                            "id": "custom_rules",
                            "type": "regex_rules",
                            "rules": [
                                {
                                    "id": "custom.partner_token",
                                    "pattern": r"\bpartner_live_[A-Za-z0-9]{12,}\b",
                                    "type": "MACHINE_SECRET",
                                    "subtype": "partner_token",
                                    "risk": "high",
                                    "suggested_action": "redact",
                                }
                            ],
                        }
                    ]
                }
            },
        }
    )
    findings = manager.scan_text("token partner_live_abcdefghijkl")
    assert findings[0].subtype == "partner_token"


def test_rule_override_add_and_disable() -> None:
    manager = HierarchicalDetectorManager(
        detectors_config={
            "preset": "default",
            "overrides": {
                "rules": {
                    "disable": ["secret.openai_api_key"],
                    "add": [
                        {
                            "id": "custom.customer_id",
                            "pattern": r"\bCUST-[0-9]{4}\b",
                            "type": "LOCAL_CONTEXT",
                            "subtype": "customer_id",
                            "risk": "medium",
                            "suggested_action": "redact",
                        }
                    ],
                }
            },
        }
    )
    subtypes = {finding.subtype for finding in manager.scan_text("sk-proj-abcdefghijklmnopqrstuvwxyz123456 CUST-1234")}
    assert "api_key" not in subtypes
    assert "customer_id" in subtypes


def test_external_tool_requires_allowlist() -> None:
    flow = build_detector_flow({"flow": {"modules": [{"id": "gitleaks", "type": "external_tool", "tool": "gitleaks"}]}})
    result = flow.scan_block(SourceBlock.from_text("hello"))
    assert result.diagnostics[0].status == "error"
    assert "not_allowlisted" in (result.diagnostics[0].error or "")


def test_hf_token_classification_adapter_with_mock(monkeypatch) -> None:
    def fake_pipeline(**_kwargs):
        def run(_text: str):
            return [{"start": 6, "end": 23, "score": 0.99, "entity_group": "EMAIL"}]

        return run

    class FakeLoader:
        @classmethod
        def from_pretrained(cls, name, **kwargs):
            assert name == "local/pii"
            assert kwargs["trust_remote_code"] is False
            return object()

    monkeypatch.setitem(
        sys.modules,
        "transformers",
        types.SimpleNamespace(
            AutoModelForTokenClassification=FakeLoader,
            AutoTokenizer=FakeLoader,
            pipeline=fake_pipeline,
        ),
    )
    manager = HierarchicalDetectorManager(
        detectors_config={
            "flow": {
                "modules": [
                    {
                        "id": "hf_pii",
                        "type": "hf_token_classification",
                        "model_name": "local/pii",
                        "threshold": 0.5,
                    }
                ]
            },
            "allow_model_download": True,
        },
    )
    findings = manager.scan_text("email howard@example.com")
    assert findings[0].subtype == "email"
    assert "models.hf_pii" in findings[0].detectors


def test_gliner_adapter_with_mock(monkeypatch) -> None:
    class FakeGLiNER:
        @classmethod
        def from_pretrained(cls, *_args, **_kwargs):
            return cls()

        def predict_entities(self, _text: str, _labels: list[str], threshold: float):
            return [{"start": 0, "end": 5, "score": threshold, "label": "person"}]

    monkeypatch.setitem(sys.modules, "gliner", types.SimpleNamespace(GLiNER=FakeGLiNER))
    manager = HierarchicalDetectorManager(
        detectors_config={
            "flow": {
                "modules": [
                    {
                        "id": "gliner_pii",
                        "type": "gliner",
                        "model_name": "local/gliner",
                        "labels": ["person"],
                        "threshold": 0.5,
                    }
                ]
            },
            "allow_model_download": True,
        },
    )
    findings = manager.scan_text("Alice")
    assert findings[0].subtype == "person"
    assert "models.gliner_pii" in findings[0].detectors


class SlowDetector(Detector):
    name = "slow"

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        time.sleep(0.05)
        return []


def test_module_timeout_fail_open_records_diagnostic() -> None:
    flow = DetectorFlow([FlowModule("slow", "python_plugin", SlowDetector(), timeout_ms=1)])
    result = flow.scan_block(SourceBlock.from_text("hello"))
    assert result.findings == []
    assert result.diagnostics[0].status == "timeout"


def test_module_timeout_is_shared_across_normalization_chunks() -> None:
    class ChunkSlowDetector(Detector):
        name = "chunk-slow"

        def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
            time.sleep(0.03)
            return []

    flow = DetectorFlow([
        FlowModule("chunk-slow", "python_plugin", ChunkSlowDetector(), timeout_ms=45),
    ])

    result = flow.scan_block(SourceBlock.from_text("x" * (NORMALIZATION_CHUNK_SIZE + 1)))

    assert result.diagnostics[0].status == "timeout"
    assert result.diagnostics[0].error == "module_timeout"


def test_flow_budget_limits_module_without_its_own_timeout() -> None:
    flow = DetectorFlow(
        [FlowModule("slow", "python_plugin", SlowDetector())],
        flow_timeout_ms=5,
    )
    started = time.perf_counter()

    result = flow.scan_block(SourceBlock.from_text("hello"))

    assert time.perf_counter() - started < 0.04
    assert result.diagnostics[0].status == "timeout"
    assert result.diagnostics[0].error == "flow_timeout"


def test_long_text_scans_sensitive_value_after_normalization_window() -> None:
    value = "howard@example.com"
    text = "x" * (NORMALIZATION_CHUNK_SIZE + 1) + " " + value
    flow = build_detector_flow()

    result = flow.scan_block(SourceBlock.from_text(text))

    findings = [finding for finding in result.findings if finding.subtype == "email"]
    assert len(findings) == 1
    finding = findings[0]
    assert text[finding.original_start : finding.original_end] == value
    assert finding.original_start > NORMALIZATION_CHUNK_SIZE


def test_overlapping_windows_deduplicate_boundary_secret_and_rebase_span() -> None:
    value = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    text = "x" * (NORMALIZATION_CHUNK_SIZE - 8) + " " + value
    flow = build_detector_flow()

    result = flow.scan_block(SourceBlock.from_text(text))

    findings = [finding for finding in result.findings if finding.subtype == "api_key"]
    assert len(findings) == 1
    finding = findings[0]
    assert text[finding.original_start : finding.original_end] == value
    assert finding.original_start == text.index(value)


def test_overlapping_windows_rebase_boundary_path_span() -> None:
    value = "/Users/alice/private/project/.env"
    text = "x" * (NORMALIZATION_CHUNK_SIZE - 8) + " " + value
    flow = build_detector_flow()

    result = flow.scan_block(SourceBlock.from_text(text))

    finding = next(finding for finding in result.findings if finding.subtype == "local_path")
    assert text[finding.original_start : finding.original_end] == value
