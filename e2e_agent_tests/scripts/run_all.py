from __future__ import annotations

import argparse
import json
from pathlib import Path

from e2e_agent_tests.scripts.common import HarnessPaths, reset_path
from e2e_agent_tests.scripts.report import generate_report
from e2e_agent_tests.scripts.run_scenario import SCENARIO_IMPLS, run_scenario


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PF realistic E2E scenarios.")
    parser.add_argument("--workdir", default=str(HarnessPaths().workdir))
    parser.add_argument("--mode", choices=["audit-only", "balanced", "strict"], default="strict")
    parser.add_argument("--scenarios", nargs="*", default=list(SCENARIO_IMPLS.keys()))
    args = parser.parse_args()
    paths = HarnessPaths(Path(args.workdir))
    reset_path(paths.artifacts)
    results = []
    for scenario_id in args.scenarios:
        scenario_workdir = Path(args.workdir) / scenario_id
        result = run_scenario(scenario_id, workdir=scenario_workdir, mode=args.mode, reset=True)
        results.append(result)
    paths.ensure()
    if paths.scenario_results.exists():
        paths.scenario_results.unlink()
    for result in results:
        with paths.scenario_results.open("a", encoding="utf-8") as f:
            f.write(json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n")
    report = generate_report(paths, Path("e2e_agent_tests/reports/latest_report.md"))
    print(json.dumps({"passed": all(r["passed"] for r in results), "count": len(results), "report": str(report)}, indent=2))
    raise SystemExit(0 if all(r["passed"] for r in results) else 1)


if __name__ == "__main__":
    main()
