from __future__ import annotations

from pathlib import Path


class PathAliasManager:
    def alias_for(self, path: str) -> str:
        p = Path(path)
        name = p.name or "path"
        if name.startswith(".") and len(p.parts) > 1:
            name = p.parts[-2] + "/" + name
        return f"/workspace/{name}"

    def join_suffix(self, base: str, suffix: str) -> str | None:
        suffix = suffix or ""
        if ".." in Path(suffix).parts:
            return None
        return str(Path(base) / suffix.lstrip("/"))
