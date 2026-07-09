from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from gateway.detectors.base import Detector
from gateway.detectors.findings import Finding, SourceBlock, safe_preview
from gateway.detectors.normalizer import NormalizedText


@dataclass(frozen=True)
class ModelDetectorConfig:
    enabled: bool = False
    model_name: str | None = None
    device: str = "cpu"
    max_window_chars: int = 4000
    batch_size: int = 4


class BaseModelDetector(Detector):
    name = "models.base"

    def __init__(self, config: ModelDetectorConfig | None = None) -> None:
        self.config = config or ModelDetectorConfig()
        self._cache: dict[str, list[Finding]] = {}
        self._loaded = False
        self._available = False

    def load(self) -> None:
        self._loaded = True
        self._available = False

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        if not self.config.enabled:
            return []
        key = hashlib.sha256(f"{self.name}:{normalized.normalized}".encode("utf-8")).hexdigest()
        if key in self._cache:
            return self._cache[key]
        try:
            if not self._loaded:
                self.load()
            if not self._available:
                return []
            findings = list(self.detect_loaded(block, normalized))
        except Exception:
            findings = []
        self._cache[key] = findings
        return findings

    def detect_loaded(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        return []

    def finding_from_span(
        self,
        *,
        block: SourceBlock,
        normalized: NormalizedText,
        start: int,
        end: int,
        label: str,
        confidence: float,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        original_start, original_end = normalized.original_span(start, end)
        return Finding.make(
            source_block_id=block.id,
            original_start=original_start,
            original_end=original_end,
            normalized_start=start,
            normalized_end=end,
            type="PII",
            subtype=label.lower(),
            confidence=confidence,
            risk="medium",
            detector=self.name,
            suggested_action="pseudonymize",
            safe_preview=safe_preview(normalized.normalized[start:end], 2),
            metadata={
                "model_name": self.config.model_name,
                "model_version": "unknown",
                "label": label,
                **(metadata or {}),
            },
        )
