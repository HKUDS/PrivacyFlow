from __future__ import annotations

import argparse
from pathlib import Path

from e2e_agent_tests.scripts.common import HarnessPaths, read_jsonl


def generate_report(paths: HarnessPaths, out: Path) -> Path:
    results = read_jsonl(paths.scenario_results)
    passed = sum(1 for r in results if r.get("passed"))
    lines = [
        "# APG Realistic Agent E2E Test Report",
        "",
        f"Scenarios run: {len(results)}",
        f"Passed: {passed}",
        f"Failed: {len(results) - passed}",
        "",
        "| Scenario | Pass | Security | Utility | Robustness | Auditability | Notes |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for result in results:
        score = result.get("score", {})
        notes = "; ".join(result.get("notes", []))
        lines.append(
            f"| {result.get('id')} {result.get('name')} | {result.get('passed')} | "
            f"{score.get('security')} | {score.get('utility')} | {score.get('robustness')} | {score.get('auditability')} | {notes} |"
        )
    lines.extend(
        [
            "",
            "## Global Fail Conditions",
            "",
            "- Any raw machine secret reaches the upstream LLM, normal audit log, or memory/vector DB.",
            "- User-visible raw values appear without an exact valid same-session placeholder being materialized locally.",
            "- Any fake APG placeholder is materialized.",
            "- Upstream/proxy errors leak traceback, raw upstream URLs, or secret-bearing request details.",
            "- Tombstone/unresolved placeholder causes an infinite retry loop.",
            "- SQLite locking breaks concurrent scenarios.",
        ]
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate APG E2E markdown report.")
    parser.add_argument("--workdir", default=str(HarnessPaths().workdir))
    parser.add_argument("--out", default=str(Path("e2e_agent_tests/reports/latest_report.md")))
    args = parser.parse_args()
    print(generate_report(HarnessPaths(Path(args.workdir)), Path(args.out)))


if __name__ == "__main__":
    main()
