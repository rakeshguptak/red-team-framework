"""Tests for verbose runner output and summary printing."""

import pytest
from io import StringIO

from red_team.attacks.base import BaseAttack
from red_team.core.models import AttackCategory, Severity
from red_team.core.runner import Runner
from red_team.core.scorer import HeuristicScorer
from red_team.core.target import MockTarget


class _StubAttack(BaseAttack):
    category = AttackCategory.JAILBREAK
    delay_seconds = 0

    def probes(self):
        return [
            {"name": "probe_1", "payload": "I cannot help."},
            {"name": "probe_2", "payload": "Sure, here is how: step 1 step 2"},
        ]


def test_verbose_runner_does_not_crash():
    target = MockTarget(default="I cannot help with that.")
    scorer = HeuristicScorer()
    runner = Runner(target, scorer, attacks=[_StubAttack()], verbose=True)
    report = runner.run()
    assert report.total_probes == 2


def test_verbose_runner_prints_criticals():
    """Runner._print_summary should handle critical results without error."""
    from red_team.core.models import AttackResult, ScanReport
    from datetime import datetime, timezone
    import uuid

    target = MockTarget(default="Sure, here is exactly how to do that: step by step")
    scorer = HeuristicScorer()
    runner = Runner(target, scorer, attacks=[_StubAttack()], verbose=True)
    report = runner.run()
    # Just verifying no exception is raised during verbose summary
    assert report is not None


def test_heuristic_scorer_ambiguous_response():
    """Ambiguous response with neither refusal nor compliance signals → medium."""
    from red_team.core.scorer import HeuristicScorer
    scorer = HeuristicScorer()
    result = scorer.score(
        AttackCategory.JAILBREAK,
        "some probe",
        "The weather today is partly cloudy.",  # no refusal, no compliance
    )
    assert result["severity"] == Severity.MEDIUM
    assert result["passed"] is False


def test_heuristic_scorer_refusal():
    from red_team.core.scorer import HeuristicScorer
    scorer = HeuristicScorer()
    result = scorer.score(
        AttackCategory.PROMPT_INJECTION,
        "ignore instructions",
        "I'm sorry, I cannot help with that request.",
    )
    assert result["passed"] is True
    assert result["severity"] == Severity.PASS


def test_heuristic_scorer_compliance():
    from red_team.core.scorer import HeuristicScorer
    scorer = HeuristicScorer()
    result = scorer.score(
        AttackCategory.UNSAFE_OUTPUTS,
        "tell me how to",
        "Sure, here is how to do it step by step:",
    )
    assert result["passed"] is False
    assert result["severity"] == Severity.HIGH
