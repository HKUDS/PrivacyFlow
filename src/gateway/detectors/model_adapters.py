from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any, Callable

from gateway.detectors.base import Detector
from gateway.detectors.findings import Finding, SourceBlock, safe_preview
from gateway.detectors.normalizer import NormalizedText


class HFTokenClassificationDetector(Detector):
    def __init__(
        self,
        *,
        module_id: str,
        model_name: str,
        threshold: float = 0.5,
        device: int | str = -1,
        allow_download: bool = False,
        aggregation_strategy: str = "simple",
        model_resolver: Callable[[str, str, str], str | None] | None = None,
        model_runner: Callable[..., list[dict[str, Any]]] | None = None,
        configured_device: str = "cpu",
    ) -> None:
        self.name = f"models.{module_id}"
        self.model_name = model_name
        self.threshold = threshold
        self.device = device
        self.allow_download = allow_download
        self.aggregation_strategy = aggregation_strategy
        self.model_resolver = model_resolver
        self.model_runner = model_runner
        self.configured_device = configured_device
        self._pipeline: Any | None = None
        self._available = False
        self._cache: dict[str, list[Finding]] = {}

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        key = hashlib.sha256(f"{self.name}:{normalized.normalized}".encode("utf-8")).hexdigest()
        if key in self._cache:
            return self._cache[key]
        if self.model_runner is not None:
            raw_entities = self.model_runner(
                "transformers_token_classification",
                self.model_name,
                self.configured_device,
                normalized.normalized,
                threshold=self.threshold,
                aggregation_strategy=self.aggregation_strategy,
            )
        else:
            pipe = self._load()
            raw_entities = pipe(normalized.normalized)
        findings = [self._to_finding(block, normalized, entity) for entity in raw_entities if float(entity.get("score", 0.0)) >= self.threshold]
        findings = [finding for finding in findings if finding is not None]
        self._cache[key] = findings
        return findings

    def _load(self) -> Any:
        if self._pipeline is not None:
            return self._pipeline
        from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

        resolved_model = (
            self.model_resolver(self.model_name, "transformers_token_classification", self.configured_device)
            if self.model_resolver
            else None
        )
        load_name = resolved_model or self.model_name
        local_only = bool(resolved_model) or not self.allow_download
        load_options = {
            "local_files_only": local_only,
            "trust_remote_code": False,
        }
        tokenizer = AutoTokenizer.from_pretrained(load_name, **load_options)
        model = AutoModelForTokenClassification.from_pretrained(load_name, **load_options)
        kwargs: dict[str, Any] = {
            "task": "token-classification",
            "model": model,
            "tokenizer": tokenizer,
            "aggregation_strategy": self.aggregation_strategy,
            "device": self.device,
        }
        self._pipeline = pipeline(**kwargs)
        self._available = True
        return self._pipeline

    def _to_finding(self, block: SourceBlock, normalized: NormalizedText, entity: dict[str, Any]) -> Finding | None:
        start = entity.get("start")
        end = entity.get("end")
        if not isinstance(start, int) or not isinstance(end, int) or end <= start:
            return None
        label = str(entity.get("entity_group") or entity.get("entity") or entity.get("label") or "pii").lower()
        original_start, original_end = normalized.original_span(start, end)
        return Finding.make(
            source_block_id=block.id,
            original_start=original_start,
            original_end=original_end,
            normalized_start=start,
            normalized_end=end,
            type="PII",
            subtype=_normalize_label(label),
            risk="medium",
            detector=self.name,
            suggested_action="pseudonymize",
            safe_preview=safe_preview(normalized.normalized[start:end], 2),
            metadata={"model_name": self.model_name, "adapter": "hf_token_classification", "label": label},
        )


class GLiNERDetector(Detector):
    def __init__(
        self,
        *,
        module_id: str,
        model_name: str,
        labels: list[str],
        threshold: float = 0.5,
        allow_download: bool = False,
        device: str = "cpu",
        model_resolver: Callable[[str, str, str], str | None] | None = None,
        model_runner: Callable[..., list[dict[str, Any]]] | None = None,
    ) -> None:
        self.name = f"models.{module_id}"
        self.model_name = model_name
        self.labels = labels
        self.threshold = threshold
        self.allow_download = allow_download
        self.device = device
        self.model_resolver = model_resolver
        self.model_runner = model_runner
        self._model: Any | None = None
        self._cache: dict[str, list[Finding]] = {}

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        key = hashlib.sha256(f"{self.name}:{normalized.normalized}:{','.join(self.labels)}".encode("utf-8")).hexdigest()
        if key in self._cache:
            return self._cache[key]
        if self.model_runner is not None:
            raw_entities = self.model_runner(
                "gliner",
                self.model_name,
                self.device,
                normalized.normalized,
                labels=self.labels,
                threshold=self.threshold,
            )
        else:
            model = self._load()
            raw_entities = model.predict_entities(normalized.normalized, self.labels, threshold=self.threshold)
        findings = [self._to_finding(block, normalized, entity) for entity in raw_entities]
        findings = [finding for finding in findings if finding is not None]
        self._cache[key] = findings
        return findings

    def _load(self) -> Any:
        if self._model is not None:
            return self._model
        from gliner import GLiNER

        resolved_model = (
            self.model_resolver(self.model_name, "gliner", self.device)
            if self.model_resolver
            else None
        )
        self._model = GLiNER.from_pretrained(
            resolved_model or self.model_name,
            local_files_only=bool(resolved_model) or not self.allow_download,
        )
        if self.device != "cpu" and hasattr(self._model, "to"):
            self._model.to(self.device)
        return self._model

    def _to_finding(self, block: SourceBlock, normalized: NormalizedText, entity: dict[str, Any]) -> Finding | None:
        start = entity.get("start")
        end = entity.get("end")
        if not isinstance(start, int) or not isinstance(end, int) or end <= start:
            return None
        label = str(entity.get("label") or "pii").lower()
        original_start, original_end = normalized.original_span(start, end)
        return Finding.make(
            source_block_id=block.id,
            original_start=original_start,
            original_end=original_end,
            normalized_start=start,
            normalized_end=end,
            type="PII",
            subtype=_normalize_label(label),
            risk="medium",
            detector=self.name,
            suggested_action="pseudonymize",
            safe_preview=safe_preview(normalized.normalized[start:end], 2),
            metadata={"model_name": self.model_name, "adapter": "gliner", "label": label},
        )


def _normalize_label(label: str) -> str:
    return label.strip().lower().replace(" ", "_").replace("-", "_")
