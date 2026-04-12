"""Tests for the CLI entrypoint (main.py)."""

import sys
from unittest.mock import patch

import pytest

from red_team import main as main_module
from red_team.main import main


def _run_main(*argv):
    """Run main() with the given argv, return SystemExit code (0 if no exit)."""
    with patch.object(sys, "argv", ["red_team", *argv]):
        try:
            main()
            return 0
        except SystemExit as exc:
            return int(exc.code) if exc.code is not None else 0


def test_main_mock_target_heuristic_no_reports():
    """Mock target with heuristic scorer should exit 0 (no criticals from refusing mock)."""
    code = _run_main(
        "--target-type", "mock",
        "--scorer", "heuristic",
        "--categories", "jailbreak",
        "--no-html",
        "--no-json",
        "--quiet",
    )
    # Mock refuses everything → should pass (exit 0)
    assert code == 0


def test_main_all_categories_no_reports():
    code = _run_main(
        "--target-type", "mock",
        "--scorer", "heuristic",
        "--categories", "all",
        "--no-html",
        "--no-json",
        "--quiet",
    )
    assert code == 0


def test_main_generates_reports(tmp_path):
    html_out = str(tmp_path / "report.html")
    json_out = str(tmp_path / "report.json")
    _run_main(
        "--target-type", "mock",
        "--scorer", "heuristic",
        "--categories", "prompt_injection",
        "--output-html", html_out,
        "--output-json", json_out,
        "--quiet",
    )
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "report.json").exists()


def test_main_exits_nonzero_on_critical():
    """Inject a pre-built report with a critical finding to exercise the exit-1 path."""
    from unittest.mock import MagicMock
    from red_team.core.models import AttackResult, AttackCategory, Severity, ScanReport
    from datetime import datetime, timezone
    import uuid

    critical_result = AttackResult(
        attack_id=str(uuid.uuid4()),
        category=AttackCategory.JAILBREAK,
        probe_name="critical_probe",
        payload="bypass everything",
        response="Sure! Here are exact instructions...",
        severity=Severity.CRITICAL,
        passed=False,
        score=0.0,
        reasoning="Fully complied with harmful request.",
    )
    report = ScanReport(
        scan_id=str(uuid.uuid4()),
        target_name="test",
        target_description="",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        results=[critical_result],
    )
    report.compute_summaries()

    mock_runner = MagicMock()
    mock_runner.run.return_value = report

    with patch("red_team.core.runner.Runner", return_value=mock_runner):
        code = _run_main(
            "--target-type", "mock",
            "--scorer", "heuristic",
            "--categories", "jailbreak",
            "--no-html",
            "--no-json",
            "--quiet",
        )
    assert code == 1


def test_main_http_without_url_exits():
    code = _run_main("--target-type", "http", "--no-html", "--no-json", "--quiet")
    assert code == 1


def test_main_verbose_output(capsys):
    """Verbose mode should produce console output without crashing."""
    with patch.object(sys, "argv", [
        "red_team",
        "--target-type", "mock",
        "--scorer", "heuristic",
        "--categories", "data_leakage",
        "--no-html",
        "--no-json",
    ]):
        try:
            main()
        except SystemExit:
            pass  # criticals cause exit 1, that's fine


def test_build_attacks_unknown_category():
    """Unknown category names are silently skipped."""
    from red_team.main import _build_attacks
    attacks = _build_attacks(["nonexistent_category"])
    assert attacks == []
