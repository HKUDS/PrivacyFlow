from __future__ import annotations

import math
import re
from collections.abc import Iterable
from urllib.parse import urlparse

from gateway.detectors.base import Detector, safe_preview
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.normalizer import NormalizedText


class EntropyContextDetector(Detector):
    name = "heuristic.entropy_context"

    TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-+/]{20,}={0,2}\b|\b[a-fA-F0-9]{32,}\b")

    def __init__(
        self,
        min_length: int = 20,
        min_entropy: float = 3.5,
        *,
        risk: str = "medium",
    ) -> None:
        self.min_length = min_length
        self.min_entropy = min_entropy
        self.risk = risk

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        text = normalized.normalized
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
            start, end = normalized.original_span(match.start(), match.end())
            yield Finding.make(
                source_block_id=block.id,
                original_start=start,
                original_end=end,
                normalized_start=match.start(),
                normalized_end=match.end(),
                type="UNKNOWN_SECRET_CANDIDATE",
                subtype="high_entropy_token",
                risk=self.risk,  # type: ignore[arg-type]
                detector=self.name,
                suggested_action="redact",
                safe_preview=safe_preview(value),
                metadata={
                    "entropy": entropy,
                    "length": len(value),
                    "source_kind": block.kind,
                },
            )


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


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
