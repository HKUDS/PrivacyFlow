from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from gateway.detectors.findings import Finding, SourceBlock, safe_preview
from gateway.detectors.normalizer import NormalizedText


class Detector(ABC):
    name: str

    @abstractmethod
    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        raise NotImplementedError


__all__ = ["Detector", "Finding", "SourceBlock", "NormalizedText", "safe_preview"]
