from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import unquote

ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\ufeff]")


def normalize_text(text: str, max_decode_depth: int = 2, max_len: int = 200_000) -> str:
    """Normalize bounded text for detection without allowing decode bombs."""
    clipped = text[:max_len]
    current = unicodedata.normalize("NFKC", ZERO_WIDTH_RE.sub("", clipped))
    for _ in range(max_decode_depth):
        decoded = html.unescape(unquote(current))
        if decoded == current or len(decoded) > max_len:
            break
        current = unicodedata.normalize("NFKC", ZERO_WIDTH_RE.sub("", decoded))
    return current
