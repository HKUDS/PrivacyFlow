from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\ufeff]")


@dataclass(frozen=True)
class NormalizedText:
    original: str
    normalized: str
    normalized_to_original: tuple[int, ...]

    def original_span(self, normalized_start: int, normalized_end: int) -> tuple[int, int]:
        if not self.normalized_to_original:
            return normalized_start, normalized_end
        start_i = max(0, min(normalized_start, len(self.normalized_to_original) - 1))
        end_i = max(0, min(max(normalized_end - 1, 0), len(self.normalized_to_original) - 1))
        return self.normalized_to_original[start_i], self.normalized_to_original[end_i] + 1


def normalize_with_mapping(text: str, max_decode_depth: int = 2, max_len: int = 200_000) -> NormalizedText:
    clipped = text[:max_len]
    normalized_chars: list[str] = []
    mapping: list[int] = []
    for i, char in enumerate(clipped):
        if ZERO_WIDTH_RE.match(char):
            continue
        replacement = unicodedata.normalize("NFKC", char)
        for out_char in replacement:
            normalized_chars.append(out_char)
            mapping.append(i)
    current = "".join(normalized_chars)
    # Decoding can shift offsets; preserve the pre-decode mapping as a conservative forensic fallback.
    for _ in range(max_decode_depth):
        decoded = html.unescape(unquote(current))
        decoded = _decode_common_escapes(decoded)
        if decoded == current or len(decoded) > max_len:
            break
        current = decoded
    return NormalizedText(clipped, current, tuple(mapping[: len(current)] or range(len(current))))


def _decode_common_escapes(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        value = match.group(1) or match.group(2)
        try:
            return chr(int(value, 16))
        except ValueError:
            return match.group(0)

    return re.sub(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})", repl, text)
