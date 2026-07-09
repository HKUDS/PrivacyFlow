from __future__ import annotations

from pathlib import Path

from e2e_agent_tests.scripts.check_leaks import scan_paths
from e2e_agent_tests.scripts.common import HarnessPaths
from e2e_agent_tests.scripts.run_scenario import run_scenario
from e2e_agent_tests.scripts.setup_test_repo import setup_test_repo
from e2e_agent_tests.scripts.run_real_api import run_real_all


STRONG_SET = [
    "scenario_01",
    "scenario_02",
    "scenario_03",
    "scenario_12",
    "scenario_14",
    "scenario_15",
    "scenario_16",
    "scenario_17",
]


def test_setup_test_repo_creates_expected_files(tmp_path: Path) -> None:
    repo = setup_test_repo(tmp_path / "repo")
    assert (repo / ".env").exists()
    assert (repo / "src/client.py").exists()
    assert "sk-apgtest" in (repo / ".env").read_text()


def test_strong_e2e_scenarios_pass_without_canary_leaks(tmp_path: Path) -> None:
    for scenario_id in STRONG_SET:
        workdir = tmp_path / scenario_id
        result = run_scenario(scenario_id, workdir=workdir, reset=True)
        assert result["passed"], result
        paths = HarnessPaths(workdir)
        assert scan_paths([paths.upstream_log, paths.audit_log, paths.external_sink_log, paths.memory_log]) == {}


def test_all_scenario_specs_exist() -> None:
    scenarios = sorted((Path(__file__).resolve().parents[1] / "scenarios").glob("scenario_*.yaml"))
    assert len(scenarios) == 14


def test_real_api_runner_requires_key(monkeypatch, tmp_path: Path) -> None:
    import argparse
    import pytest

    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    args = argparse.Namespace(
        workdir=str(tmp_path / "real"),
        report=str(tmp_path / "report.md"),
        model="deepseek-v4-flash",
        max_tokens=16,
        mode="strict",
        scenarios=["scenario_01"],
    )
    with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY"):
        run_real_all(args)
