from __future__ import annotations

import base64
import hmac
import re
import time
from dataclasses import dataclass
from hashlib import sha256

from gateway.compat import normalize_namespace

PLACEHOLDER_RE = re.compile(
    r"<(?P<namespace>PF|APG):v1:(?P<kind>[a-z_]+):(?P<handle>[^:<>]+):"
    r"(?P<session>[^:<>]+):(?P<issued>\d{1,15}):(?P<mac>[A-Za-z0-9_-]+)>"
)
PF_PLACEHOLDER_FORMAT_EXAMPLES = (
    "<PF:v1:pii:...>",
    "<PF:v1:secret:...>",
)
PF_PLACEHOLDER_FORMAT_EXAMPLE = PF_PLACEHOLDER_FORMAT_EXAMPLES[0]
APG_PLACEHOLDER_FORMAT_EXAMPLES = (
    "<APG:v1:pii:...>",
    "<APG:v1:secret:...>",
)
APG_PLACEHOLDER_FORMAT_EXAMPLE = APG_PLACEHOLDER_FORMAT_EXAMPLES[0]
PLACEHOLDER_FORMAT_EXAMPLES = PF_PLACEHOLDER_FORMAT_EXAMPLES + APG_PLACEHOLDER_FORMAT_EXAMPLES


def span_is_within_placeholder_format_example(text: str, start: int, end: int) -> bool:
    """Return whether a non-empty span is wholly inside the reserved format example."""
    if start < 0 or end <= start or end > len(text):
        return False
    for example in PLACEHOLDER_FORMAT_EXAMPLES:
        example_start = text.find(example)
        while example_start >= 0:
            example_end = example_start + len(example)
            if example_start <= start and end <= example_end:
                return True
            example_start = text.find(example, example_start + 1)
    return False


@dataclass(frozen=True)
class ParsedPlaceholder:
    raw: str
    kind: str
    handle_id: str
    session_id: str
    issued_at: int
    mac: str
    suffix: str = ""
    namespace: str = "PF"


class PlaceholderSigner:
    def __init__(self, secret: str, workspace_id: str = "default", policy_hash: str = "default", namespace: str = "PF") -> None:
        self.secret = secret.encode("utf-8")
        self.workspace_id = workspace_id
        self.policy_hash = policy_hash
        self.namespace = normalize_namespace(namespace)

    def issue(self, kind: str, handle_id: str, session_id: str, issued_at: int | None = None) -> str:
        # Prevent colon injection: fields must not contain ':' which is the MAC body delimiter
        _require_no_delimiter(kind, "kind")
        _require_no_delimiter(handle_id, "handle_id")
        _require_no_delimiter(session_id, "session_id")
        issued = int(time.time()) if issued_at is None else int(issued_at)
        mac = self._mac(kind, handle_id, session_id, issued)
        return f"<{self.namespace}:v1:{kind}:{handle_id}:{session_id}:{issued}:{mac}>"

    def parse(self, text: str) -> list[ParsedPlaceholder]:
        parsed: list[ParsedPlaceholder] = []
        for match in PLACEHOLDER_RE.finditer(text):
            suffix = ""
            end = match.end()
            suffix_match = re.match(r"(/[A-Za-z0-9._\-/]+)", text[end:])
            if suffix_match:
                raw_suffix = suffix_match.group(1)
                # Reject suffixes containing path traversal patterns
                if not _is_safe_suffix(raw_suffix):
                    continue
                suffix = raw_suffix
            parsed.append(
                ParsedPlaceholder(
                    match.group(0),
                    match.group("kind"),
                    match.group("handle"),
                    match.group("session"),
                    int(match.group("issued")),
                    match.group("mac"),
                    suffix,
                    match.group("namespace"),
                )
            )
        return parsed

    def is_valid(self, ph: ParsedPlaceholder) -> bool:
        return hmac.compare_digest(ph.mac, self._mac(ph.kind, ph.handle_id, ph.session_id, ph.issued_at))

    def _mac(self, kind: str, handle_id: str, session_id: str, issued_at: int) -> str:
        body = f"v1:{kind}:{handle_id}:{session_id}:{self.workspace_id}:{issued_at}:{self.policy_hash}".encode("utf-8")
        digest = hmac.new(self.secret, body, sha256).digest()[:12]
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _require_no_delimiter(value: str, field_name: str) -> None:
    """Reject values containing ':' or '<' or '>' to prevent MAC injection."""
    if ":" in value or "<" in value or ">" in value:
        raise ValueError(
            f"Field '{field_name}' contains invalid characters: "
            f"must not contain ':', '<', or '>'"
        )


_SAFE_SUFFIX_RE = re.compile(r"^/[A-Za-z0-9._\-/]+$")


def _is_safe_suffix(suffix: str) -> bool:
    """Reject path suffixes that attempt traversal via '..' or '//'."""
    if "/../" in suffix or suffix.endswith("/.."):
        return False
    if "/./" in suffix or suffix.endswith("/."):
        return False
    if "//" in suffix:
        return False
    return bool(_SAFE_SUFFIX_RE.match(suffix))
