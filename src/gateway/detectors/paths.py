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
    def __init__(
        self,
        *,
        detect_unix_home: bool = True,
        detect_macos_private: bool = True,
        detect_shell_config: bool = True,
        detect_windows_user: bool = True,
        exclude_patterns: list[str] | tuple[str, ...] | None = None,
        path_risk: str = "medium",
    ) -> None:
        enabled = (detect_unix_home, detect_macos_private, detect_shell_config, detect_windows_user, detect_windows_user)
        self.patterns = tuple(pattern for pattern, include in zip(self.PATTERNS, enabled, strict=True) if include)
        self.exclude_patterns = tuple(exclude_patterns or ())
        self.path_risk = path_risk

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        for pattern in self.patterns:
            for match in pattern.finditer(normalized.normalized):
                value = match.group(0).rstrip(self.TRAILING_PUNCTUATION)
                if not value:
                    continue
                if any(fnmatch.fnmatch(value, pattern) for pattern in self.exclude_patterns):
                    continue
                normalized_end = match.start() + len(value)
                start, end = normalized.original_span(match.start(), normalized_end)
                yield Finding.make(
                    source_block_id=block.id,
                    original_start=start,
                    original_end=end,
                    normalized_start=match.start(),
                    normalized_end=normalized_end,
                    type="LOCAL_CONTEXT",
                    subtype="local_path",
                    risk=self.path_risk,  # type: ignore[arg-type]
                    detector=self.name,
                    validators=("local_path_shape",),
                    suggested_action="alias",
                    safe_preview=_path_preview(value),
                )


def _path_preview(value: str) -> str:
    parts = re.split(r"[/\\]+", value.strip("/\\"))
    if len(parts) <= 2:
        return "/<path>"
    return f"/{parts[0]}/.../{parts[-1]}"
