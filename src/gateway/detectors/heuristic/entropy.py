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
            if _assignment_lhs(value, text, match.end()):
                continue
            if _structured_identifier_in_code_context(value, text, match.start()):
                continue
            if _inside_address_like_identifier(text, match.start(), match.end()):
                continue
            if _ssh_public_key_payload(text, match.start()):
                continue
            if _labeled_digest(value, text, match.start()):
                continue
            if value.startswith("workspace/") or "/workspace/" in value:
                continue
            if _tool_identifier(value):
                continue
            if _path_like_token(value, text, match.start(), match.end()):
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


def _assignment_lhs(value: str, text: str, end: int) -> bool:
    identifier = value.rstrip("=")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier) is None:
        return False
    return value.endswith("=") or text[end:].lstrip(" \t").startswith("=")


def _structured_identifier_in_code_context(value: str, text: str, start: int) -> bool:
    candidate = value.rstrip("=")
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*(?:_[A-Za-z0-9-]+){2,}", candidate) is None:
        return False
    paragraph_start = text.rfind("\n\n", 0, start)
    context_start = max(paragraph_start + 2 if paragraph_start >= 0 else 0, start - 512)
    prefix = text[context_start:start]
    if prefix.endswith("."):
        return True
    return re.search(r"(?:--(?:kb-names|backends?|model)|python\d*(?:\.\d+)?\s+-m)\b", prefix, re.I) is not None


def _inside_address_like_identifier(text: str, start: int, end: int) -> bool:
    left = max(text.rfind(char, 0, start) for char in (" ", "\n", "\t", "\"", "'", "`")) + 1
    right_candidates = [
        pos
        for char in (" ", "\n", "\t", "\"", "'", "`")
        if (pos := text.find(char, end)) != -1
    ]
    right = min(right_candidates) if right_candidates else len(text)
    token = text[left:right].strip("(),;")
    return "@" in token and re.fullmatch(r"[^\s@]+@[A-Za-z0-9.-]+", token) is not None


def _ssh_public_key_payload(text: str, start: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[line_start:start]
    return re.search(r"(?:ssh-(?:rsa|ed25519)|ecdsa-[A-Za-z0-9@._+-]+)\s+$", prefix, re.I) is not None


def _labeled_digest(value: str, text: str, start: int) -> bool:
    if re.fullmatch(r"[a-fA-F0-9]{32,128}", value) is None:
        return False
    prefix = text[max(0, start - 48) : start]
    return re.search(r"(?:sha-?(?:1|224|256|384|512)|md5|checksum|digest|commit)\s*[:=]?\s*$", prefix, re.I) is not None


def _path_like_token(value: str, text: str, start: int, end: int) -> bool:
    if "/" not in value:
        return False
    if start > 0 and text[start - 1] in {"/", ".", "~"}:
        return True
    if value.startswith(("/", "./", "../", "~/")):
        return True
    if re.match(r"\.(?:py|pyi|js|jsx|ts|tsx|json|ya?ml|toml|md|txt|log|sh|zsh|bash)\b", text[end:], re.I):
        return True
    if re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", value) and ("-" in value or "_" in value):
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
        "opt",
        "packages",
        "scripts",
        "src",
        "test",
        "tests",
        "usr",
        "var",
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
