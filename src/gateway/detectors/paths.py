from __future__ import annotations

import re
from collections.abc import Iterable

from gateway.detectors.base import Detector
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.normalizer import NormalizedText


class PathDetector(Detector):
    name = "paths"

    PATTERNS = (
        re.compile(r"(?<!\w)/(?:Users|home)/[A-Za-z0-9._-]+/[^\s\"'<>)]*"),
        re.compile(r"(?<!\w)/private/[^\s\"'<>)]*"),
        re.compile(r"(?<!\w)~/(?:\.ssh|\.aws|\.config)(?:/[^\s\"'<>)]*)?"),
        re.compile(r"(?<!\w)%(?:USERPROFILE|APPDATA)%\\[^\s\"'<>)]*", re.I),
        re.compile(r"(?<!\w)[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\[^\s\"'<>)]*"),
    )
    KNOWN_CREDENTIAL_NAMES = (".env", "id_rsa", "id_ed25519", "credentials.json", "kubeconfig", ".npmrc", ".pypirc")

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        for pattern in self.PATTERNS:
            for match in pattern.finditer(normalized.normalized):
                value = match.group(0)
                subtype = "credential_file" if any(name in value for name in self.KNOWN_CREDENTIAL_NAMES) else "local_path"
                start, end = normalized.original_span(match.start(), match.end())
                yield Finding.make(
                    source_block_id=block.id,
                    original_start=start,
                    original_end=end,
                    normalized_start=match.start(),
                    normalized_end=match.end(),
                    type="CREDENTIAL_FILE" if subtype == "credential_file" else "LOCAL_CONTEXT",
                    subtype=subtype,
                    confidence=0.9,
                    risk="high" if subtype == "credential_file" else "medium",
                    detector=self.name,
                    validators=("local_path_shape",),
                    suggested_action="redact" if subtype == "credential_file" else "warn",
                    safe_preview=_path_preview(value),
                )


def _path_preview(value: str) -> str:
    parts = re.split(r"[/\\]+", value.strip("/\\"))
    if len(parts) <= 2:
        return "/<path>"
    return f"/{parts[0]}/.../{parts[-1]}"
