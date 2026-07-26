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

    TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-+/]{20,}={0,2}\b|\b[a-fA-F0-9]{32,}\b")

    def __init__(
        self,
        min_length: int = 20,
        min_entropy: float = 3.5,
        *,
        context_window: int = 80,
        sensitive_words: list[str] | tuple[str, ...] | None = None,
        false_positive_hints: list[str] | tuple[str, ...] | None = None,
        sensitive_risk: str = "high",
        contextless_risk: str = "medium",
        sensitive_action: str = "redact",
        contextless_action: str = "warn",
    ) -> None:
        self.min_length = min_length
        self.min_entropy = min_entropy
        self.context_window = context_window
        self.sensitive_words = tuple(sensitive_words) if sensitive_words is not None else SENSITIVE_WORDS
        self.false_positive_hints = tuple(false_positive_hints) if false_positive_hints is not None else FALSE_POSITIVE_HINTS
        self.sensitive_risk = sensitive_risk
        self.contextless_risk = contextless_risk
        self.sensitive_action = sensitive_action
        self.contextless_action = contextless_action

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        text = normalized.normalized
        lowered = text.lower()
        for match in self.TOKEN_RE.finditer(text):
            value = match.group(0)
            if len(value) < self.min_length or value.startswith("APG"):
                continue
            if value.startswith("workspace/") or "/workspace/" in value:
                continue
            if _tool_identifier(value):
                continue
            if _path_like_token(value, text, match.end()):
                continue
            if _inside_plain_http_url(text, match.start(), match.end()):
                continue
            entropy = shannon_entropy(value)
            if entropy < self.min_entropy:
                continue
            window_start = max(0, match.start() - self.context_window)
            window_end = min(len(text), match.end() + self.context_window)
            context = lowered[window_start:window_end]
            sensitive_context = any(word.lower() in context for word in self.sensitive_words)
            weak_context = any(word.lower() in context for word in self.false_positive_hints)
            if sensitive_context:
                confidence = 0.82
                risk = self.sensitive_risk
                action = self.sensitive_action
            else:
                confidence = 0.55
                risk = self.contextless_risk
                action = self.contextless_action
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
                suggested_action=action,  # type: ignore[arg-type]
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


def _path_like_token(value: str, text: str, end: int) -> bool:
    if "/" not in value:
        return False
    if value.startswith(("/", "./", "../", "~/")):
        return True
    if re.match(r"\.(?:py|pyi|js|jsx|ts|tsx|json|ya?ml|toml|md|txt|log|sh|zsh|bash)\b", text[end:], re.I):
        return True
    first_segment = value.split("/", 1)[0].lower()
    return first_segment in {
        "app",
        "apps",
        "bin",
        "config",
        "docs",
        "e2e_agent_tests",
        "examples",
        "lib",
        "logs",
        "packages",
        "scripts",
        "src",
        "test",
        "tests",
    }


def _inside_plain_http_url(text: str, start: int, end: int) -> bool:
    left = max(text.rfind(" ", 0, start), text.rfind("\n", 0, start), text.rfind("\t", 0, start)) + 1
    right_candidates = [pos for pos in (text.find(" ", end), text.find("\n", end), text.find("\t", end)) if pos != -1]
    right = min(right_candidates) if right_candidates else len(text)
    token = text[left:right].strip("\"'`<>()[],")
    if not token.startswith(("http://", "https://")):
        return False
    parsed = urlparse(token)
    return bool(parsed.netloc) and not parsed.query and "@" not in parsed.netloc
