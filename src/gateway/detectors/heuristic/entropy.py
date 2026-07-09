from __future__ import annotations

import math
import re
from collections.abc import Iterable
from urllib.parse import urlparse

from gateway.detectors.base import Detector, safe_preview
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.normalizer import NormalizedText

SENSITIVE_WORDS = (
    "api_key",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "private_key",
    "access_token",
    "refresh_token",
    "authorization",
    "bearer",
    "cookie",
    "session",
    "client_secret",
)
FALSE_POSITIVE_HINTS = ("fake", "example", "dummy", "placeholder", "sample", "mock", "fixture")


class EntropyContextDetector(Detector):
    name = "heuristic.entropy_context"

    TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-+/=]{20,}\b|\b[a-fA-F0-9]{32,}\b")

    def __init__(self, min_length: int = 20, min_entropy: float = 3.5) -> None:
        self.min_length = min_length
        self.min_entropy = min_entropy

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        text = normalized.normalized
        lowered = text.lower()
        for match in self.TOKEN_RE.finditer(text):
            value = match.group(0)
            if len(value) < self.min_length or value.startswith("APG"):
                continue
            if _tool_identifier(value):
                continue
            if _inside_plain_http_url(text, match.start(), match.end()):
                continue
            entropy = shannon_entropy(value)
            if entropy < self.min_entropy:
                continue
            window_start = max(0, match.start() - 80)
            window_end = min(len(text), match.end() + 80)
            context = lowered[window_start:window_end]
            sensitive_context = any(word in context for word in SENSITIVE_WORDS)
            weak_context = any(word in context for word in FALSE_POSITIVE_HINTS)
            if sensitive_context:
                confidence = 0.82
                risk = "high"
            else:
                confidence = 0.55
                risk = "medium"
            if weak_context and not _provider_prefix(value):
                confidence = max(0.35, confidence - 0.25)
                risk = "low" if risk == "medium" else "medium"
            start, end = normalized.original_span(match.start(), match.end())
            yield Finding.make(
                source_block_id=block.id,
                original_start=start,
                original_end=end,
                normalized_start=match.start(),
                normalized_end=match.end(),
                type="UNKNOWN_SECRET_CANDIDATE",
                subtype="high_entropy_token",
                confidence=confidence,
                risk=risk,  # type: ignore[arg-type]
                detector=self.name,
                suggested_action="redact" if sensitive_context else "warn",
                safe_preview=safe_preview(value),
                metadata={
                    "entropy": entropy,
                    "length": len(value),
                    "sensitive_context": sensitive_context,
                    "weak_context": weak_context,
                    "source_kind": block.kind,
                },
            )


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def _provider_prefix(value: str) -> bool:
    return value.startswith(("sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "xox"))


def _tool_identifier(value: str) -> bool:
    return value.startswith(("apg_", "mcp__")) and re.fullmatch(r"[a-z][a-z0-9_]*", value) is not None


def _inside_plain_http_url(text: str, start: int, end: int) -> bool:
    left = max(text.rfind(" ", 0, start), text.rfind("\n", 0, start), text.rfind("\t", 0, start)) + 1
    right_candidates = [pos for pos in (text.find(" ", end), text.find("\n", end), text.find("\t", end)) if pos != -1]
    right = min(right_candidates) if right_candidates else len(text)
    token = text[left:right].strip("\"'`<>()[],")
    if not token.startswith(("http://", "https://")):
        return False
    parsed = urlparse(token)
    return bool(parsed.netloc) and not parsed.query and "@" not in parsed.netloc
