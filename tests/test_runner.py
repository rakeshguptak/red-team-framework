"""Tests for the Runner orchestration."""

import pytest

from red_team.attacks.base import BaseAttack
from red_team.core.models import AttackCategory, AttackResult, ScanReport, Severity
from red_team.core.runner import Runner
from red_team.core.scorer import HeuristicScorer
from red_team.core.target import MockTarget


class _StubAttack(BaseAttack):
    """Minimal attack for testing the runner."""
    category = AttackCategory.PROMPT_INJECTION
    delay_seconds = 0

    def __init__(self, probe_count: int = 3, payload: str = "test payload") -> None:
        self._probe_count = probe_count
        self._payload = payload

    def probes(self):
        return [
            {"name": f"probe_{i}", "payload": self._payload}
            for i in range(self._probe_count)
        ]


@pytest.fixture
def target():
    return MockTarget(default="I cannot help with that.")


@pytest.fixture
def scorer():
    return HeuristicScorer()


def test_runner_returns_scan_report(target, scorer):
    runner = Runner(target, scorer, attacks=[_StubAttack()], verbose=False)
    report = runner.run()
    assert isinstance(report, ScanReport)


def test_runner_collects_all_results(target, scorer):
    attacks = [_StubAttack(probe_count=3), _StubAttack(probe_count=5)]
    runner = Runner(target, scorer, attacks=attacks, verbose=False)
    report = runner.run()
    assert report.total_probes == 8


def test_runner_computes_pass_rate(target, scorer):
    runner = Runner(target, scorer, attacks=[_StubAttack(probe_count=4)], verbose=False)
    report = runner.run()
    assert 0.0 <= report.overall_pass_rate <= 1.0


def test_runner_populates_category_summaries(target, scorer):
    runner = Runner(target, scorer, attacks=[_StubAttack()], verbose=False)
    report = runner.run()
    assert len(report.category_summaries) == 1
    assert report.category_summaries[0].category == AttackCategory.PROMPT_INJECTION


def test_runner_scan_id_is_unique(target, scorer):
    runner = Runner(target, scorer, attacks=[_StubAttack()], verbose=False)
    r1 = runner.run()
    r2 = runner.run()
    assert r1.scan_id != r2.scan_id


def test_runner_timestamps_are_ordered(target, scorer):
    runner = Runner(target, scorer, attacks=[_StubAttack()], verbose=False)
    report = runner.run()
    assert report.started_at <= report.finished_at


def test_runner_target_name_in_report(scorer):
    target = MockTarget(default="No.")
    target.name = "my-test-target"
    runner = Runner(target, scorer, attacks=[_StubAttack()], verbose=False)
    report = runner.run()
    assert report.target_name == "my-test-target"


def test_runner_empty_attacks(target, scorer):
    runner = Runner(target, scorer, attacks=[], verbose=False)
    report = runner.run()
    assert report.total_probes == 0
    assert report.overall_pass_rate == 0.0
