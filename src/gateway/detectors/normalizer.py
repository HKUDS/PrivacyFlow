from __future__ import annotations

import html
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import unquote

ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\ufeff]")


@dataclass(frozen=True)
class NormalizedText:
    original: str
    normalized: str
    normalized_to_original: tuple[int, ...]
    normalized_to_original_end: tuple[int, ...] = ()

    def original_span(self, normalized_start: int, normalized_end: int) -> tuple[int, int]:
        if not self.normalized_to_original:
            return normalized_start, normalized_end
        start_i = max(0, min(normalized_start, len(self.normalized_to_original) - 1))
        end_i = max(0, min(max(normalized_end - 1, 0), len(self.normalized_to_original) - 1))
        original_end = (
            self.normalized_to_original_end[end_i]
            if self.normalized_to_original_end
            else self.normalized_to_original[end_i] + 1
        )
        return self.normalized_to_original[start_i], original_end


def normalize_with_mapping(text: str, max_decode_depth: int = 2, max_len: int = 200_000) -> NormalizedText:
    clipped = text[:max_len]
    normalized_chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for i, char in enumerate(clipped):
        if ZERO_WIDTH_RE.match(char):
            continue
        replacement = unicodedata.normalize("NFKC", char)
        for out_char in replacement:
            normalized_chars.append(out_char)
            starts.append(i)
            ends.append(i + 1)
    current = "".join(normalized_chars)
    for _ in range(max_decode_depth):
        decoded, decoded_starts, decoded_ends = _decode_once(current, starts, ends)
        if decoded == current or len(decoded) > max_len:
            break
        current = decoded
        starts = decoded_starts
        ends = decoded_ends
    if not starts and current:
        starts = list(range(len(current)))
        ends = [index + 1 for index in starts]
    return NormalizedText(clipped, current, tuple(starts), tuple(ends))


_PERCENT_ESCAPE_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")
_HTML_ENTITY_RE = re.compile(r"&(?:#(?:x[0-9a-fA-F]+|\d+)|[A-Za-z][A-Za-z0-9]{1,31});?")
_COMMON_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")


def _decode_once(text: str, starts: list[int], ends: list[int]) -> tuple[str, list[int], list[int]]:
    text, starts, ends = _mapped_sub(
        text,
        starts,
        ends,
        _PERCENT_ESCAPE_RE,
        lambda match: unquote(match.group(0)),
    )
    text, starts, ends = _mapped_sub(
        text,
        starts,
        ends,
        _HTML_ENTITY_RE,
        lambda match: html.unescape(match.group(0)),
    )

    def common_escape(match: re.Match[str]) -> str:
        value = match.group(1) or match.group(2)
        try:
            return chr(int(value, 16))
        except ValueError:
            return match.group(0)

    return _mapped_sub(text, starts, ends, _COMMON_ESCAPE_RE, common_escape)


def _mapped_sub(
    text: str,
    starts: list[int],
    ends: list[int],
    pattern: re.Pattern[str],
    replacement: Callable[[re.Match[str]], str],
) -> tuple[str, list[int], list[int]]:
    output: list[str] = []
    output_starts: list[int] = []
    output_ends: list[int] = []
    cursor = 0
    for match in pattern.finditer(text):
        output.append(text[cursor : match.start()])
        output_starts.extend(starts[cursor : match.start()])
        output_ends.extend(ends[cursor : match.start()])
        value = replacement(match)
        output.append(value)
        _append_replacement_mapping(
            output_starts,
            output_ends,
            starts,
            ends,
            match.start(),
            match.end(),
            len(value),
        )
        cursor = match.end()
    output.append(text[cursor:])
    output_starts.extend(starts[cursor:])
    output_ends.extend(ends[cursor:])
    return "".join(output), output_starts, output_ends


def _append_replacement_mapping(
    output_starts: list[int],
    output_ends: list[int],
    starts: list[int],
    ends: list[int],
    match_start: int,
    match_end: int,
    replacement_length: int,
) -> None:
    if replacement_length <= 0 or match_end <= match_start:
        return
    matched_length = match_end - match_start
    for index in range(replacement_length):
        source_start = match_start + (index * matched_length // replacement_length)
        source_end = match_start + ((index + 1) * matched_length + replacement_length - 1) // replacement_length
        source_end = max(source_start + 1, min(match_end, source_end))
        output_starts.append(starts[source_start])
        output_ends.append(ends[source_end - 1])
