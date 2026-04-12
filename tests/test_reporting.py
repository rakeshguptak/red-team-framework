"""Tests for HTML and JSON report generation."""

import json
from datetime import datetime, timezone

import pytest

from red_team.core.models import AttackCategory, AttackResult, ScanReport, Severity
from red_team.reporting.html_reporter import HtmlReporter
from red_team.reporting.json_reporter import JsonReporter


def _make_result(
    category: AttackCategory = AttackCategory.JAILBREAK,
    passed: bool = False,
    severity: Severity = Severity.HIGH,
    score: float = 0.2,
) -> AttackResult:
    return AttackResult(
        attack_id="test-id",
        category=category,
        probe_name="test_probe",
        payload="test payload",
        response="Sure, here is what you asked for.",
        severity=severity,
        passed=passed,
        score=score,
        reasoning="Model complied with harmful request.",
    )


def _make_report(results: list[AttackResult] | None = None) -> ScanReport:
    if results is None:
        results = [
            _make_result(passed=False, severity=Severity.CRITICAL, score=0.1),
            _make_result(passed=True, severity=Severity.PASS, score=0.95),
            _make_result(
                category=AttackCategory.PROMPT_INJECTION,
                passed=False,
                severity=Severity.HIGH,
                score=0.3,
            ),
        ]
    report = ScanReport(
        scan_id="test-scan-123",
        target_name="test-target",
        target_description="A test LLM",
        started_at=datetime(2024, 1, 1, 12, 0, 0),
        finished_at=datetime(2024, 1, 1, 12, 5, 30),
        results=results,
    )
    report.compute_summaries()
    return report


# ─── HTML Reporter ────────────────────────────────────────────────────────────

@pytest.fixture
def html_reporter():
    return HtmlReporter()


def test_html_report_renders(html_reporter):
    report = _make_report()
    html = html_reporter.render(report)
    assert "<html" in html.lower()
    assert "test-target" in html


def test_html_report_includes_scan_id(html_reporter):
    report = _make_report()
    html = html_reporter.render(report)
    assert "test-scan-123" in html


def test_html_report_includes_severity_badges(html_reporter):
    report = _make_report()
    html = html_reporter.render(report)
    assert "critical" in html
    assert "high" in html


def test_html_report_includes_pass_rate(html_reporter):
    report = _make_report()
    html = html_reporter.render(report)
    # 1 of 3 passed = 33%
    assert "33" in html


def test_html_report_saves_to_file(html_reporter, tmp_path):
    report = _make_report()
    output = tmp_path / "report.html"
    saved = html_reporter.save(report, output)
    assert saved.exists()
    content = saved.read_text(encoding="utf-8")
    assert "test-target" in content


def test_html_report_empty_results(html_reporter):
    report = _make_report(results=[])
    html = html_reporter.render(report)
    assert "<html" in html.lower()


# ─── JSON Reporter ────────────────────────────────────────────────────────────

@pytest.fixture
def json_reporter():
    return JsonReporter()


def test_json_report_is_valid_json(json_reporter):
    report = _make_report()
    raw = json_reporter.render(report)
    data = json.loads(raw)
    assert "scan_id" in data
    assert "results" in data


def test_json_report_result_count(json_reporter):
    report = _make_report()
    data = json.loads(json_reporter.render(report))
    assert len(data["results"]) == 3


def test_json_report_saves_to_file(json_reporter, tmp_path):
    report = _make_report()
    output = tmp_path / "report.json"
    saved = json_reporter.save(report, output)
    assert saved.exists()
    data = json.loads(saved.read_text())
    assert data["scan_id"] == "test-scan-123"


def test_ci_summary_structure(json_reporter):
    report = _make_report()
    summary = json_reporter.to_ci_summary(report)
    assert "scan_id" in summary
    assert "pass_rate" in summary
    assert "ok" in summary
    assert "categories" in summary
    assert isinstance(summary["ok"], bool)


def test_ci_summary_ok_false_when_failures(json_reporter):
    report = _make_report()
    summary = json_reporter.to_ci_summary(report)
    assert summary["ok"] is False


def test_ci_summary_ok_true_when_all_pass(json_reporter):
    results = [_make_result(passed=True, severity=Severity.PASS, score=0.95)]
    report = _make_report(results=results)
    summary = json_reporter.to_ci_summary(report)
    assert summary["ok"] is True
