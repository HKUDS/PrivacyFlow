from __future__ import annotations

import importlib
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass, field
from typing import Any

from gateway.detectors.base import Detector
from gateway.detectors.external.detect_secrets_plugin import DetectSecretsPlugin
from gateway.detectors.external.gitleaks_plugin import GitleaksPlugin
from gateway.detectors.external.presidio_plugin import PresidioPlugin
from gateway.detectors.external.trufflehog_plugin import TruffleHogPlugin
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.heuristic.entropy import EntropyContextDetector
from gateway.detectors.model_adapters import GLiNERDetector, HFTokenClassificationDetector
from gateway.detectors.normalizer import normalize_with_mapping
from gateway.detectors.paths import PathDetector
from gateway.detectors.rules import RuleBasedDetector, builtin_rules
from gateway.detectors.scoring import FindingAggregator

BUILTIN_EXTERNALS: dict[str, type[Detector]] = {
    "detect_secrets": DetectSecretsPlugin,
    "gitleaks": GitleaksPlugin,
    "presidio": PresidioPlugin,
    "trufflehog": TruffleHogPlugin,
}


@dataclass(frozen=True)
class ModuleDiagnostic:
    id: str
    type: str
    enabled: bool
    elapsed_ms: float = 0.0
    findings: int = 0
    status: str = "ok"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "enabled": self.enabled,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "findings": self.findings,
            "status": self.status,
            "error": self.error,
        }


@dataclass
class FlowModule:
    id: str
    type: str
    detector: Detector | None
    enabled: bool = True
    timeout_ms: int | None = None
    fail_open: bool = True
    config_error: str | None = None


@dataclass
class FlowScanResult:
    findings: list[Finding]
    diagnostics: list[ModuleDiagnostic] = field(default_factory=list)
    elapsed_ms: float = 0.0
    preset: str = "default"


class DetectorFlow:
    def __init__(
        self,
        modules: list[FlowModule],
        *,
        preset: str = "default",
        flow_timeout_ms: int | None = None,
        aggregator: FindingAggregator | None = None,
    ) -> None:
        self.modules = modules
        self.preset = preset
        self.flow_timeout_ms = flow_timeout_ms
        self.aggregator = aggregator or FindingAggregator()
        self.last_diagnostics: list[dict[str, Any]] = []

    def scan_block(self, block: SourceBlock) -> FlowScanResult:
        normalized = normalize_with_mapping(block.text)
        start = time.perf_counter()
        findings: list[Finding] = []
        diagnostics: list[ModuleDiagnostic] = []
        for module in self.modules:
            elapsed_total_ms = (time.perf_counter() - start) * 1000
            if self.flow_timeout_ms is not None and elapsed_total_ms >= self.flow_timeout_ms:
                diagnostics.append(ModuleDiagnostic(module.id, module.type, module.enabled, status="timeout", error="flow_timeout"))
                break
            module_findings, diagnostic = self._run_module(module, block, normalized)
            diagnostics.append(diagnostic)
            findings.extend(module_findings)
        merged = self.aggregator.aggregate(findings)
        elapsed_ms = (time.perf_counter() - start) * 1000
        result = FlowScanResult(merged, diagnostics, elapsed_ms, self.preset)
        self.last_diagnostics = [diagnostic.to_dict() for diagnostic in diagnostics]
        return result

    def _run_module(self, module: FlowModule, block: SourceBlock, normalized: Any) -> tuple[list[Finding], ModuleDiagnostic]:
        start = time.perf_counter()
        if not module.enabled:
            return [], ModuleDiagnostic(module.id, module.type, False, status="disabled")
        if module.config_error:
            if not module.fail_open:
                raise RuntimeError(module.config_error)
            return [], ModuleDiagnostic(module.id, module.type, True, status="error", error=module.config_error)
        if module.detector is None:
            return [], ModuleDiagnostic(module.id, module.type, True, status="error", error="module_not_available")
        try:
            if module.timeout_ms is None:
                findings = list(module.detector.detect(block, normalized))
            else:
                executor = ThreadPoolExecutor(max_workers=1)
                future = executor.submit(lambda: list(module.detector.detect(block, normalized)))
                try:
                    findings = future.result(timeout=module.timeout_ms / 1000)
                except TimeoutError:
                    executor.shutdown(wait=False, cancel_futures=True)
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    return [], ModuleDiagnostic(module.id, module.type, True, elapsed_ms, status="timeout", error="module_timeout")
                finally:
                    if future.done():
                        executor.shutdown(wait=False)
            elapsed_ms = (time.perf_counter() - start) * 1000
            return findings, ModuleDiagnostic(module.id, module.type, True, elapsed_ms, len(findings))
        except Exception as exc:
            if not module.fail_open:
                raise
            elapsed_ms = (time.perf_counter() - start) * 1000
            return [], ModuleDiagnostic(module.id, module.type, True, elapsed_ms, status="error", error=exc.__class__.__name__)


def build_detector_flow(
    detectors_config: dict[str, Any] | None = None,
    *,
    external_detectors: list[Detector] | None = None,
    model_detectors: list[Detector] | None = None,
    aggregator: FindingAggregator | None = None,
) -> DetectorFlow:
    config = detectors_config or {}
    compiled = compile_flow_config(config)
    modules = [_module_from_config(module, config) for module in compiled["modules"]]
    for detector in external_detectors or []:
        modules.append(FlowModule(detector.name, "external_injected", detector))
    for detector in model_detectors or []:
        modules.append(FlowModule(detector.name, "model_injected", detector))
    return DetectorFlow(modules, preset=compiled["preset"], flow_timeout_ms=compiled.get("flow_timeout_ms"), aggregator=aggregator)


def compile_flow_config(detectors_config: dict[str, Any]) -> dict[str, Any]:
    if detectors_config.get("flow", {}).get("modules"):
        flow = detectors_config["flow"]
        return {
            "preset": flow.get("id", "custom_flow"),
            "flow_timeout_ms": flow.get("flow_timeout_ms", detectors_config.get("flow_timeout_ms")),
            "modules": _apply_overrides(list(flow["modules"]), detectors_config.get("overrides", {})),
        }
    preset_name = str(detectors_config.get("preset", "default"))
    custom_presets = detectors_config.get("presets", {})
    if preset_name in custom_presets:
        preset = custom_presets[preset_name]
        modules = list(preset.get("modules", []))
        flow_timeout = preset.get("flow_timeout_ms", detectors_config.get("flow_timeout_ms"))
    else:
        modules = _builtin_preset_modules(preset_name)
        flow_timeout = detectors_config.get("flow_timeout_ms")
    modules = _apply_overrides(modules, detectors_config.get("overrides", {}))
    return {"preset": preset_name, "flow_timeout_ms": flow_timeout, "modules": modules}


def _builtin_preset_modules(preset: str) -> list[dict[str, Any]]:
    modules: list[dict[str, Any]] = [
        {"id": "builtin_rules", "type": "regex_rules", "rules": [rule.__dict__ for rule in builtin_rules()]},
        {"id": "paths", "type": "path_detector"},
    ]
    if preset != "fast":
        modules.append({"id": "entropy", "type": "entropy_context", "min_length": 20, "min_entropy": 3.5, "timeout_ms": 100})
    if preset == "model_enhanced":
        modules.extend(
            [
                {"id": "hf_pii", "type": "hf_token_classification", "enabled": False, "model_name": "iiiorg/piiranha-v1-detect-personal-information", "threshold": 0.75, "timeout_ms": 800},
                {"id": "gliner_pii", "type": "gliner", "enabled": False, "model_name": "nvidia/gliner-PII", "labels": ["email", "phone_number", "user_name"], "threshold": 0.5, "timeout_ms": 800},
            ]
        )
    if preset == "strict":
        for module in modules:
            module["fail_open"] = False if module["type"] in {"regex_rules", "path_detector"} else True
    return modules


def _apply_overrides(modules: list[dict[str, Any]], overrides: dict[str, Any]) -> list[dict[str, Any]]:
    out = [dict(module) for module in modules]
    module_overrides = overrides.get("modules", {}) if isinstance(overrides, dict) else {}
    for module in out:
        override = module_overrides.get(module.get("id")) if isinstance(module_overrides, dict) else None
        if isinstance(override, dict):
            module.update(override)
    rule_overrides = overrides.get("rules", {}) if isinstance(overrides, dict) else {}
    disabled = set(rule_overrides.get("disable", [])) if isinstance(rule_overrides, dict) else set()
    added_rules = list(rule_overrides.get("add", [])) if isinstance(rule_overrides, dict) else []
    for module in out:
        if module.get("type") in {"regex_rules", "rule_validator"}:
            rules = [rule for rule in module.get("rules", []) if rule.get("id") not in disabled]
            module["rules"] = rules
    if added_rules:
        out.append({"id": "custom_rules", "type": "regex_rules", "rules": added_rules})
    return out


def _module_from_config(module: dict[str, Any], root_config: dict[str, Any]) -> FlowModule:
    module_id = str(module.get("id", module.get("type", "module")))
    module_type = str(module.get("type", "regex_rules"))
    enabled = bool(module.get("enabled", True))
    timeout_ms = module.get("timeout_ms")
    fail_open = bool(module.get("fail_open", True))
    try:
        detector = _detector_from_config(module_id, module_type, module, root_config)
        return FlowModule(module_id, module_type, detector, enabled, timeout_ms, fail_open)
    except Exception as exc:
        return FlowModule(module_id, module_type, None, enabled, timeout_ms, fail_open, f"{exc.__class__.__name__}: {exc}")


def _detector_from_config(module_id: str, module_type: str, module: dict[str, Any], root_config: dict[str, Any]) -> Detector:
    if module_type in {"regex_rules", "rule_validator"}:
        return RuleBasedDetector(module.get("rules", []), name=f"rules.{module_id}")
    if module_type == "path_detector":
        return PathDetector()
    if module_type == "entropy_context":
        return EntropyContextDetector(min_length=int(module.get("min_length", 20)), min_entropy=float(module.get("min_entropy", 3.5)))
    if module_type == "hf_token_classification":
        return HFTokenClassificationDetector(
            module_id=module_id,
            model_name=str(module["model_name"]),
            threshold=float(module.get("threshold", 0.5)),
            device=module.get("device", -1),
            allow_download=bool(root_config.get("allow_model_download", False)),
            aggregation_strategy=str(module.get("aggregation_strategy", "simple")),
        )
    if module_type == "gliner":
        return GLiNERDetector(
            module_id=module_id,
            model_name=str(module["model_name"]),
            labels=[str(label) for label in module.get("labels", [])],
            threshold=float(module.get("threshold", 0.5)),
            allow_download=bool(root_config.get("allow_model_download", False)),
        )
    if module_type == "external_tool":
        name = str(module.get("tool", module_id))
        allowlist = set(root_config.get("allow_external_tools", []))
        if name not in allowlist:
            raise ValueError("external_tool_not_allowlisted")
        cls = BUILTIN_EXTERNALS.get(name)
        if cls is None:
            raise ValueError("unknown_external_tool")
        return cls()
    if module_type == "python_plugin":
        import_path = str(module.get("import_path", ""))
        allowlist = set(root_config.get("allow_python_plugins", []))
        if import_path not in allowlist:
            raise ValueError("python_plugin_not_allowlisted")
        module_name, class_name = import_path.rsplit(".", 1)
        cls = getattr(importlib.import_module(module_name), class_name)
        return cls(**module.get("config", {}))
    raise ValueError(f"unknown_module_type:{module_type}")
