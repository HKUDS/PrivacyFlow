from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable

from gateway.detectors.base import Detector
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.normalizer import NormalizedText


class PathDetector(Detector):
    name = "paths"
    TRAILING_PUNCTUATION = ".,;:!?]}"

    PATTERNS = (
        re.compile(r"(?<!\w)/(?:Users|home)/[A-Za-z0-9._-]+/[^\s\"'<>)]*"),
        re.compile(r"(?<!\w)/private/[^\s\"'<>)]*"),
        re.compile(r"(?<!\w)~/(?:\.ssh|\.aws|\.config)(?:/[^\s\"'<>)]*)?"),
        re.compile(r"(?<!\w)%(?:USERPROFILE|APPDATA)%\\[^\s\"'<>)]*", re.I),
        re.compile(r"(?<!\w)[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\[^\s\"'<>)]*"),
    )
    KNOWN_CREDENTIAL_NAMES = (".env", "id_rsa", "id_ed25519", "credentials.json", "kubeconfig", ".npmrc", ".pypirc")

    def __init__(
        self,
        *,
        detect_unix_home: bool = True,
        detect_macos_private: bool = True,
        detect_shell_config: bool = True,
        detect_windows_user: bool = True,
        credential_names: list[str] | tuple[str, ...] | None = None,
        exclude_patterns: list[str] | tuple[str, ...] | None = None,
        path_risk: str = "medium",
        credential_risk: str = "high",
        path_action: str = "warn",
        credential_action: str = "redact",
    ) -> None:
        enabled = (detect_unix_home, detect_macos_private, detect_shell_config, detect_windows_user, detect_windows_user)
        self.patterns = tuple(pattern for pattern, include in zip(self.PATTERNS, enabled, strict=True) if include)
        self.credential_names = tuple(credential_names) if credential_names is not None else self.KNOWN_CREDENTIAL_NAMES
        self.exclude_patterns = tuple(exclude_patterns or ())
        self.path_risk = path_risk
        self.credential_risk = credential_risk
        self.path_action = path_action
        self.credential_action = credential_action

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        for pattern in self.patterns:
            for match in pattern.finditer(normalized.normalized):
                value = match.group(0).rstrip(self.TRAILING_PUNCTUATION)
                if not value:
                    continue
                if any(fnmatch.fnmatch(value, pattern) for pattern in self.exclude_patterns):
                    continue
                subtype = "credential_file" if any(name in value for name in self.credential_names) else "local_path"
                normalized_end = match.start() + len(value)
                start, end = normalized.original_span(match.start(), normalized_end)
                yield Finding.make(
                    source_block_id=block.id,
                    original_start=start,
                    original_end=end,
                    normalized_start=match.start(),
                    normalized_end=normalized_end,
                    type="CREDENTIAL_FILE" if subtype == "credential_file" else "LOCAL_CONTEXT",
                    subtype=subtype,
                    confidence=0.9,
                    risk=self.credential_risk if subtype == "credential_file" else self.path_risk,  # type: ignore[arg-type]
                    detector=self.name,
                    validators=("local_path_shape",),
                    suggested_action=self.credential_action if subtype == "credential_file" else self.path_action,  # type: ignore[arg-type]
                    safe_preview=_path_preview(value),
                )


def _path_preview(value: str) -> str:
    parts = re.split(r"[/\\]+", value.strip("/\\"))
    if len(parts) <= 2:
        return "/<path>"
    return f"/{parts[0]}/.../{parts[-1]}"
