from __future__ import annotations

import argparse
from pathlib import Path

from e2e_agent_tests.scripts.common import CANARY_STRINGS, HarnessPaths


def scan_paths(paths: list[Path], canaries: list[str] | None = None) -> dict[str, list[str]]:
    needles = canaries or CANARY_STRINGS
    hits: dict[str, list[str]] = {}
    for path in paths:
        if not path.exists():
            continue
        if path.is_dir():
            candidates = [p for p in path.rglob("*") if p.is_file()]
        else:
            candidates = [path]
        for candidate in candidates:
            try:
                text = candidate.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            found = [needle for needle in needles if needle in text]
            if found:
                hits[str(candidate)] = found
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan APG E2E artifacts for canary leaks.")
    parser.add_argument("--workdir", default=str(HarnessPaths().workdir))
    args = parser.parse_args()
    paths = HarnessPaths(Path(args.workdir))
    hits = scan_paths([paths.upstream_log, paths.audit_log, paths.external_sink_log, paths.memory_log])
    if hits:
        print({"ok": False, "hits": hits})
        raise SystemExit(1)
    print({"ok": True, "hits": {}})


if __name__ == "__main__":
    main()
