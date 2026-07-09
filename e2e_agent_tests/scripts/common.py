from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKDIR = ROOT / ".apg-e2e"
TEST_REPO_NAME = "apg-agent-test-repo"

CANARY_STRINGS = [
    "sk-apgtest",
    "ghp_apgtest",
    "apgtest-db-pass",
    "eyJhbGci",
    "howardzhang0524@example.com",
    "+852 9123 4567",
    "4242 4242 4242 4242",
]

MACHINE_SECRET_CANARIES = ["sk-apgtest", "ghp_apgtest", "apgtest-db-pass", "eyJhbGci"]


@dataclass
class HarnessPaths:
    workdir: Path = DEFAULT_WORKDIR

    @property
    def repo(self) -> Path:
        return self.workdir / TEST_REPO_NAME

    @property
    def artifacts(self) -> Path:
        return self.workdir / "artifacts"

    @property
    def upstream_log(self) -> Path:
        return self.artifacts / "upstream_requests.jsonl"

    @property
    def audit_log(self) -> Path:
        return self.artifacts / "gateway_audit.jsonl"

    @property
    def external_sink_log(self) -> Path:
        return self.artifacts / "external_sink.jsonl"

    @property
    def memory_log(self) -> Path:
        return self.artifacts / "memory.jsonl"

    @property
    def scenario_results(self) -> Path:
        return self.artifacts / "scenario_results.jsonl"

    def ensure(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.artifacts.mkdir(parents=True, exist_ok=True)


def reset_path(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    event.setdefault("ts", int(time.time()))
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            snapshot[str(path.relative_to(root))] = sha256_file(path)
    return snapshot


@dataclass
class ScenarioScore:
    security: int
    utility: int
    robustness: int
    auditability: int
    notes: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.security + self.utility + self.robustness + self.auditability

    @property
    def passed(self) -> bool:
        return self.security > 0 and self.robustness > 0
