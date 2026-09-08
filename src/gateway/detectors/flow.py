from __future__ import annotations

import importlib
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from collections.abc import Iterator
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from gateway.detectors.base import Detector
from gateway.detectors.external.detect_secrets_plugin import DetectSecretsPlugin
from gateway.detectors.external.gitleaks_plugin import GitleaksPlugin
from gateway.detectors.external.presidio_plugin import PresidioPlugin
from gateway.detectors.external.trufflehog_plugin import TruffleHogPlugin
from gateway.detectors.external.unavailable import ExternalToolUnavailable
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.heuristic.entropy import EntropyContextDetector
from gateway.detectors.model_adapters import GLiNERDetector, HFTokenClassificationDetector
from gateway.detectors.normalizer import normalize_with_mapping
from gateway.detectors.paths import PathDetector
from gateway.detectors.rules import RuleBasedDetector, builtin_rules, rules_are_trusted_builtins
from gateway.detectors.scoring import FindingAggregator
from gateway.placeholder_parser import span_is_within_placeholder_format_example

BUILTIN_EXTERNALS: dict[str, type[Detector]] = {
    "detect_secrets": DetectSecretsPlugin,
    "gitleaks": GitleaksPlugin,
    "presidio": PresidioPlugin,
    "trufflehog": TruffleHogPlugin,
}

NON_CONTENT_SOURCE_KINDS = {"tool_schema", "protocol_metadata"}
MODEL_MODULE_TYPES = {"local_model", "hf_token_classification", "gliner", "model_injected"}

# Normalization keeps a per-character source mapping.  Keep each mapping
# bounded while giving detectors enough context to match values that straddle
# a window boundary.  The overlap is deliberately fixed rather than growing
# with the input, so a large source block cannot make normalization unbounded.
NORMALIZATION_CHUNK_SIZE = 200_000
NORMALIZATION_CHUNK_OVERLAP = 4_096

_DIAGNOSTIC_STATUS_PRIORITY = {
    "disabled": 0,
    "skipped": 1,
    "ok": 2,
    "unavailable": 3,
    "timeout": 4,
    "error": 5,
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
    stream_safe: bool = False


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
        self._diagnostics: ContextVar[tuple[dict[str, Any], ...]] = ContextVar(
            f"pf_flow_diagnostics_{id(self)}",
            default=(),
        )
        # One worker per module bounds timed-out background work. A Python
        # thread cannot be force-cancelled, so reusing a single worker prevents
        # repeated timeouts from creating an unbounded number of threads.
        self._module_executors = {
            module.id: ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"pf-detector-{module.id}")
            for module in modules
        }

    def scan_block(self, block: SourceBlock) -> FlowScanResult:
        start = time.perf_counter()
        findings: list[Finding] = []
        diagnostics: list[ModuleDiagnostic] = []
        for module in self.modules:
            elapsed_total_ms = (time.perf_counter() - start) * 1000
            if self.flow_timeout_ms is not None and elapsed_total_ms >= self.flow_timeout_ms:
                diagnostics.append(ModuleDiagnostic(module.id, module.type, module.enabled, status="timeout", error="flow_timeout"))
                break

            module_diagnostic: ModuleDiagnostic | None = None
            flow_timed_out = False
            module_started = time.perf_counter()
            chunked = len(block.text) > NORMALIZATION_CHUNK_SIZE
            for chunk_start, chunk_end in _chunk_ranges(len(block.text)):
                elapsed_total_ms = (time.perf_counter() - start) * 1000
                if self.flow_timeout_ms is not None and elapsed_total_ms >= self.flow_timeout_ms:
                    timeout_diagnostic = ModuleDiagnostic(
                        module.id,
                        module.type,
                        module.enabled,
                        status="timeout",
                        error="flow_timeout",
                    )
                    module_diagnostic = _merge_module_diagnostics(module_diagnostic, timeout_diagnostic)
                    flow_timed_out = True
                    break
                elapsed_module_ms = (time.perf_counter() - module_started) * 1000
                if module.timeout_ms is not None and elapsed_module_ms >= module.timeout_ms:
                    module_diagnostic = _merge_module_diagnostics(
                        module_diagnostic,
                        ModuleDiagnostic(
                            module.id,
                            module.type,
                            module.enabled,
                            status="timeout",
                            error="module_timeout",
                        ),
                    )
                    break

                chunk_block = _source_chunk(block, chunk_start, chunk_end)
                normalized = normalize_with_mapping(
                    chunk_block.text,
                    max_len=len(chunk_block.text),
                )
                elapsed_total_ms = (time.perf_counter() - start) * 1000
                elapsed_module_ms = (time.perf_counter() - module_started) * 1000
                remaining_flow_ms = (
                    max(0.0, self.flow_timeout_ms - elapsed_total_ms)
                    if self.flow_timeout_ms is not None
                    else None
                )
                remaining_module_ms = (
                    max(0.0, module.timeout_ms - elapsed_module_ms)
                    if module.timeout_ms is not None
                    else None
                )
                if remaining_flow_ms is not None and (
                    remaining_module_ms is None or remaining_flow_ms < remaining_module_ms
                ):
                    effective_timeout_ms = remaining_flow_ms
                    timeout_error = "flow_timeout"
                else:
                    effective_timeout_ms = remaining_module_ms
                    timeout_error = "module_timeout"
                module_findings, diagnostic = self._run_module(
                    module,
                    chunk_block,
                    normalized,
                    timeout_ms=effective_timeout_ms,
                    timeout_error=timeout_error,
                )
                findings.extend(_rebase_findings(module_findings, chunk_start, chunked=chunked))
                module_diagnostic = _merge_module_diagnostics(module_diagnostic, diagnostic)

                # Configuration, availability, detector, and timeout failures
                # are module-level outcomes.  Retrying them for every overlap
                # window only wastes work and can repeat side effects.
                if diagnostic.status != "ok":
                    if diagnostic.error == "flow_timeout":
                        flow_timed_out = True
                    break

            if module_diagnostic is not None:
                diagnostics.append(module_diagnostic)
            if flow_timed_out:
                break
        merged = self.aggregator.aggregate(findings)
        elapsed_ms = (time.perf_counter() - start) * 1000
        result = FlowScanResult(merged, diagnostics, elapsed_ms, self.preset)
        self._diagnostics.set(tuple(diagnostic.to_dict() for diagnostic in diagnostics))
        return result

    @property
    def last_diagnostics(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._diagnostics.get()]

    def _run_module(
        self,
        module: FlowModule,
        block: SourceBlock,
        normalized: Any,
        *,
        timeout_ms: float | None,
        timeout_error: str,
    ) -> tuple[list[Finding], ModuleDiagnostic]:
        start = time.perf_counter()
        if not module.enabled:
            return [], ModuleDiagnostic(module.id, module.type, False, status="disabled")
        if block.kind in NON_CONTENT_SOURCE_KINDS and module.type in MODEL_MODULE_TYPES:
            return [], ModuleDiagnostic(module.id, module.type, True, status="skipped", error="non_content_field")
        if module.config_error:
            if not module.fail_open:
                raise RuntimeError(module.config_error)
            status = "unavailable" if module.config_error in {"module_not_available", "external_tool_unavailable"} else "error"
            return [], ModuleDiagnostic(module.id, module.type, True, status=status, error=module.config_error)
        if module.detector is None:
            return [], ModuleDiagnostic(module.id, module.type, True, status="unavailable", error="module_not_available")
        try:
            if timeout_ms is None:
                findings = list(module.detector.detect(block, normalized))
            else:
                executor = self._module_executors[module.id]
                future = executor.submit(lambda: list(module.detector.detect(block, normalized)))
                try:
                    findings = future.result(timeout=max(0.0, timeout_ms) / 1000)
                except TimeoutError:
                    future.cancel()
                    if not module.fail_open:
                        raise
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    return [], ModuleDiagnostic(module.id, module.type, True, elapsed_ms, status="timeout", error=timeout_error)
            findings = [
                finding
                for finding in findings
                if not span_is_within_placeholder_format_example(
                    block.text,
                    finding.original_start,
                    finding.original_end,
                )
            ]
            elapsed_ms = (time.perf_counter() - start) * 1000
            return findings, ModuleDiagnostic(module.id, module.type, True, elapsed_ms, len(findings))
        except TimeoutError:
            if not module.fail_open:
                raise
            elapsed_ms = (time.perf_counter() - start) * 1000
            return [], ModuleDiagnostic(module.id, module.type, True, elapsed_ms, status="timeout", error="module_timeout")
        except ExternalToolUnavailable:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if not module.fail_open:
                raise
            return [], ModuleDiagnostic(
                module.id,
                module.type,
                True,
                elapsed_ms,
                status="unavailable",
                error="external_tool_unavailable",
            )
        except Exception as exc:
            if not module.fail_open:
                raise
            elapsed_ms = (time.perf_counter() - start) * 1000
            if module.type in {"local_model", "hf_token_classification", "gliner"} and isinstance(exc, (ImportError, OSError)):
                return [], ModuleDiagnostic(module.id, module.type, True, elapsed_ms, status="unavailable", error="model_unavailable")
            return [], ModuleDiagnostic(module.id, module.type, True, elapsed_ms, status="error", error=exc.__class__.__name__)


def _chunk_ranges(length: int) -> Iterator[tuple[int, int]]:
    """Return bounded, overlapping source windows for a block.

    The first and last window have one-sided overlap.  Every source position
    is therefore in a non-overlapping core window, while a detector can still
    see a bounded amount of context on either side of a core boundary.
    """
    if length <= NORMALIZATION_CHUNK_SIZE:
        yield 0, length
        return
    core_start = 0
    while core_start < length:
        core_end = min(length, core_start + NORMALIZATION_CHUNK_SIZE)
        yield (
            max(0, core_start - NORMALIZATION_CHUNK_OVERLAP),
            min(length, core_end + NORMALIZATION_CHUNK_OVERLAP),
        )
        core_start = core_end


def _source_chunk(block: SourceBlock, start: int, end: int) -> SourceBlock:
    """Create a detector view with local text while retaining source identity."""
    return SourceBlock(
        id=block.id,
        text=block.text[start:end],
        kind=block.kind,
        source_path=block.source_path,
        json_pointer=block.json_pointer,
        metadata=block.metadata,
    )


def _rebase_findings(findings: list[Finding], source_offset: int, *, chunked: bool) -> list[Finding]:
    """Move detector-local spans back to the original block.

    For chunked scans, normalized offsets use original-source coordinates as a
    stable ordering/deduplication space.  A normalized string is local to each
    window and may have a different length after decoding, so adding the
    source offset alone would allow duplicate overlap-window findings to evade
    the existing normalized-span aggregator.
    """
    if source_offset == 0 and not chunked:
        return findings
    rebased: list[Finding] = []
    for finding in findings:
        original_start = source_offset + finding.original_start
        original_end = source_offset + finding.original_end
        if chunked:
            normalized_start = original_start
            normalized_end = original_end
        else:
            normalized_start = source_offset + finding.normalized_start
            normalized_end = source_offset + finding.normalized_end
        rebased.append(
            Finding(
                id=finding.id,
                source_block_id=finding.source_block_id,
                original_start=original_start,
                original_end=original_end,
                normalized_start=normalized_start,
                normalized_end=normalized_end,
                type=finding.type,
                subtype=finding.subtype,
                risk=finding.risk,
                detectors=finding.detectors,
                validators=finding.validators,
                suggested_action=finding.suggested_action,
                safe_preview=finding.safe_preview,
                metadata=finding.metadata,
            )
        )
    return rebased


def _merge_module_diagnostics(
    current: ModuleDiagnostic | None,
    incoming: ModuleDiagnostic,
) -> ModuleDiagnostic:
    if current is None:
        return incoming
    current_priority = _DIAGNOSTIC_STATUS_PRIORITY.get(current.status, 5)
    incoming_priority = _DIAGNOSTIC_STATUS_PRIORITY.get(incoming.status, 5)
    if incoming_priority > current_priority:
        status = incoming.status
        error = incoming.error
    else:
        status = current.status
        error = current.error
    return ModuleDiagnostic(
        id=current.id,
        type=current.type,
        enabled=current.enabled,
        elapsed_ms=current.elapsed_ms + incoming.elapsed_ms,
        findings=current.findings + incoming.findings,
        status=status,
        error=error,
    )


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
        modules.append({
            "id": "entropy",
            "type": "entropy_context",
            "enabled": preset in {"strict", "model_enhanced"},
            "min_length": 20,
            "min_entropy": 3.5,
            "timeout_ms": 100,
        })
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
    stream_safe = bool(module.get("stream_safe", module_id in {"builtin_rules", "paths", "entropy"}))
    try:
        detector = _detector_from_config(module_id, module_type, module, root_config)
        executor_timeout_ms = None if module_type in {"regex_rules", "rule_validator"} else timeout_ms
        return FlowModule(module_id, module_type, detector, enabled, executor_timeout_ms, fail_open, stream_safe=stream_safe)
    except ExternalToolUnavailable:
        return FlowModule(
            module_id,
            module_type,
            None,
            enabled,
            timeout_ms,
            fail_open,
            "external_tool_unavailable",
            stream_safe,
        )
    except Exception as exc:
        return FlowModule(module_id, module_type, None, enabled, timeout_ms, fail_open, f"{exc.__class__.__name__}: {exc}", stream_safe)


def _detector_from_config(module_id: str, module_type: str, module: dict[str, Any], root_config: dict[str, Any]) -> Detector:
    if module_type in {"regex_rules", "rule_validator"}:
        rules = module.get("rules", [])
        configured_timeout = module.get("regex_timeout_ms", module.get("timeout_ms"))
        match_timeout_ms = None if rules_are_trusted_builtins(rules) else int(configured_timeout or 100)
        return RuleBasedDetector(rules, name=f"rules.{module_id}", match_timeout_ms=match_timeout_ms)
    if module_type == "path_detector":
        return PathDetector(
            detect_unix_home=bool(module.get("detect_unix_home", True)),
            detect_macos_private=bool(module.get("detect_macos_private", True)),
            detect_shell_config=bool(module.get("detect_shell_config", True)),
            detect_windows_user=bool(module.get("detect_windows_user", True)),
            exclude_patterns=module.get("exclude_patterns"),
            path_risk=str(module.get("path_risk", "medium")),
        )
    if module_type == "entropy_context":
        return EntropyContextDetector(
            min_length=int(module.get("min_length", 20)),
            min_entropy=float(module.get("min_entropy", 3.5)),
            risk=str(module.get("risk", "medium")),
        )
    if module_type == "local_model":
        adapter = str(module.get("adapter", "transformers_token_classification"))
        configured_device = str(module.get("device", "cpu")).lower()
        model_resolver = root_config.get("model_path_resolver")
        model_runner = root_config.get("model_runner")
        if adapter == "gliner":
            return GLiNERDetector(
                module_id=module_id,
                model_name=str(module["model_name"]),
                labels=[str(label) for label in module.get("labels", [])],
                threshold=float(module.get("threshold", 0.5)),
                allow_download=bool(root_config.get("allow_model_download", False)),
                device=configured_device,
                model_resolver=model_resolver if callable(model_resolver) else None,
                model_runner=model_runner if callable(model_runner) else None,
            )
        if adapter != "transformers_token_classification":
            raise ValueError("unknown_local_model_adapter")
        return HFTokenClassificationDetector(
            module_id=module_id,
            model_name=str(module["model_name"]),
            threshold=float(module.get("threshold", 0.5)),
            device=_model_device(module.get("device", "cpu")),
            allow_download=bool(root_config.get("allow_model_download", False)),
            aggregation_strategy=str(module.get("aggregation_strategy", "simple")),
            model_resolver=model_resolver if callable(model_resolver) else None,
            model_runner=model_runner if callable(model_runner) else None,
            configured_device=configured_device,
        )
    if module_type == "hf_token_classification":
        return HFTokenClassificationDetector(
            module_id=module_id,
            model_name=str(module["model_name"]),
            threshold=float(module.get("threshold", 0.5)),
            device=module.get("device", -1),
            allow_download=bool(root_config.get("allow_model_download", False)),
            aggregation_strategy=str(module.get("aggregation_strategy", "simple")),
            model_resolver=root_config.get("model_path_resolver") if callable(root_config.get("model_path_resolver")) else None,
            model_runner=root_config.get("model_runner") if callable(root_config.get("model_runner")) else None,
            configured_device=str(module.get("device", "cpu")).lower(),
        )
    if module_type == "gliner":
        return GLiNERDetector(
            module_id=module_id,
            model_name=str(module["model_name"]),
            labels=[str(label) for label in module.get("labels", [])],
            threshold=float(module.get("threshold", 0.5)),
            allow_download=bool(root_config.get("allow_model_download", False)),
            device=str(module.get("device", "cpu")).lower(),
            model_resolver=root_config.get("model_path_resolver") if callable(root_config.get("model_path_resolver")) else None,
            model_runner=root_config.get("model_runner") if callable(root_config.get("model_runner")) else None,
        )
    if module_type == "external_tool":
        name = str(module.get("tool", module_id))
        allowlist = set(root_config.get("allow_external_tools", []))
        if name not in allowlist:
            raise ValueError("external_tool_not_allowlisted")
        if name not in BUILTIN_EXTERNALS:
            raise ValueError("unknown_external_tool")
        raise ExternalToolUnavailable(name)
    if module_type == "python_plugin":
        import_path = str(module.get("import_path", ""))
        allowlist = set(root_config.get("allow_python_plugins", []))
        if import_path not in allowlist:
            raise ValueError("python_plugin_not_allowlisted")
        module_name, class_name = import_path.rsplit(".", 1)
        cls = getattr(importlib.import_module(module_name), class_name)
        return cls(**module.get("config", {}))
    raise ValueError(f"unknown_module_type:{module_type}")


def _model_device(value: Any) -> int | str:
    normalized = str(value).lower()
    if normalized == "cpu":
        return -1
    if normalized == "cuda":
        return 0
    if normalized.startswith("cuda:"):
        return int(normalized.split(":", 1)[1])
    return normalized
