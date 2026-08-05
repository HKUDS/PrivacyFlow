from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

# A path segment that would make string prefix matching differ from pathlib's
# normalization (`..`/`.` segments, doubled or trailing separators).
_NON_CANONICAL_SEGMENT = re.compile(r"(^|/)(?:\.\.?)(/|$)|/{2}|/$")


class PathAliasManager:
    def alias_for(self, path: str) -> str:
        p = Path(path)
        name = p.name or "path"
        if name.startswith(".") and len(p.parts) > 1:
            name = p.parts[-2] + "/" + name
        digest = hashlib.blake2s(str(p).encode("utf-8"), digest_size=4).hexdigest()
        return f"/workspace/{name}-{digest}"

    def join_suffix(self, base: str, suffix: str) -> str | None:
        suffix = suffix or ""
        if ".." in Path(suffix).parts:
            return None
        return str(Path(base) / suffix.lstrip("/"))

    def relative_suffix(self, parent: str, child: str) -> str | None:
        sep = "\\" if "\\" in parent or "\\" in child else "/"
        # Fast path for canonical absolute paths (no `.`/`..`/doubled-or-trailing
        # separator that pathlib would normalize). Active-path lookup calls this
        # O(N^2) times per request, and each PurePosixPath construction +
        # relative_to is expensive; string prefix matching is ~12x faster.
        if (
            sep == "/"
            and not _NON_CANONICAL_SEGMENT.search(parent)
            and not _NON_CANONICAL_SEGMENT.search(child)
            and parent.startswith(sep)
            and child.startswith(sep)
        ):
            if child == parent:
                return ""
            prefix = parent + sep
            if child.startswith(prefix):
                return "/" + child[len(prefix) :]
            return None
        path_type = PureWindowsPath if sep == "\\" else PurePosixPath
        try:
            relative = path_type(child).relative_to(path_type(parent))
        except ValueError:
            return None
        if not relative.parts:
            return ""
        return "/" + "/".join(relative.parts)
