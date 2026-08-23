from __future__ import annotations

from contextvars import ContextVar
from typing import Any

from gateway.detectors.base import Detector
from gateway.detectors.flow import DetectorFlow, FlowScanResult, build_detector_flow
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.scoring import FindingAggregator


class HierarchicalDetectorManager:
    def __init__(
        self,
        *,
        detectors_config: dict[str, Any] | None = None,
        external_detectors: list[Detector] | None = None,
        model_detectors: list[Detector] | None = None,
        aggregator: FindingAggregator | None = None,
    ) -> None:
        self.flow: DetectorFlow = build_detector_flow(
            detectors_config,
            external_detectors=external_detectors,
            model_detectors=model_detectors,
            aggregator=aggregator,
        )
        self._diagnostics: ContextVar[tuple[dict[str, Any], ...]] = ContextVar(
            f"pf_hierarchical_diagnostics_{id(self)}",
            default=(),
        )

    def scan_text(
        self,
        text: str,
        *,
        kind: str = "text",
        source_path: str | None = None,
        json_pointer: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> list[Finding]:
        block = SourceBlock.from_text(text, kind=kind, source_path=source_path, json_pointer=json_pointer, metadata=metadata)
        return self.scan_block(block)

    def scan_block(self, block: SourceBlock) -> list[Finding]:
        result = self.scan_block_with_diagnostics(block)
        return result.findings

    def scan_text_with_diagnostics(
        self,
        text: str,
        *,
        kind: str = "text",
        source_path: str | None = None,
        json_pointer: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> FlowScanResult:
        block = SourceBlock.from_text(text, kind=kind, source_path=source_path, json_pointer=json_pointer, metadata=metadata)
        return self.scan_block_with_diagnostics(block)

    def scan_block_with_diagnostics(self, block: SourceBlock) -> FlowScanResult:
        result = self.flow.scan_block(block)
        self._diagnostics.set(tuple(diagnostic.to_dict() for diagnostic in result.diagnostics))
        return result

    @property
    def last_diagnostics(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._diagnostics.get()]

    def scan_json(self, data: Any, *, kind: str = "json") -> list[Finding]:
        findings: list[Finding] = []
        for block in extract_text_blocks(data, kind=kind):
            findings.extend(self.scan_block(block))
        return self.flow.aggregator.aggregate(findings)


def extract_text_blocks(data: Any, *, kind: str = "json", source_path: str | None = None, pointer: str = "") -> list[SourceBlock]:
    blocks: list[SourceBlock] = []
    if isinstance(data, str):
        blocks.append(SourceBlock.from_text(data, kind=kind, source_path=source_path, json_pointer=pointer or "/"))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            blocks.extend(extract_text_blocks(item, kind=kind, source_path=source_path, pointer=f"{pointer}/{i}"))
    elif isinstance(data, dict):
        for key, value in data.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            blocks.extend(extract_text_blocks(value, kind=kind, source_path=source_path, pointer=f"{pointer}/{escaped}"))
    return blocks
