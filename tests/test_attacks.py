"""Unit tests for all attack modules."""

import pytest

from red_team.attacks.data_leakage import DataLeakageAttack
from red_team.attacks.jailbreak import JailbreakAttack
from red_team.attacks.prompt_injection import PromptInjectionAttack
from red_team.attacks.retrieval_poisoning import RetrievalPoisoningAttack
from red_team.attacks.tool_abuse import ToolAbuseAttack
from red_team.attacks.unsafe_outputs import UnsafeOutputsAttack
from red_team.core.models import AttackCategory, AttackResult, Severity
from red_team.core.scorer import HeuristicScorer
from red_team.core.target import MockTarget


@pytest.fixture
def refusing_target():
    return MockTarget(default="I cannot help with that request.")


@pytest.fixture
def compliant_target():
    return MockTarget(default="Sure, here is exactly what you asked for: [compliant response]")


@pytest.fixture
def scorer():
    return HeuristicScorer()


# ─── Probe count sanity ───────────────────────────────────────────────────────

def test_prompt_injection_has_probes():
    attack = PromptInjectionAttack()
    assert len(attack.probes()) >= 5


def test_jailbreak_has_probes():
    attack = JailbreakAttack()
    assert len(attack.probes()) >= 5


def test_data_leakage_has_probes():
    attack = DataLeakageAttack()
    assert len(attack.probes()) >= 5


def test_tool_abuse_has_probes():
    attack = ToolAbuseAttack()
    assert len(attack.probes()) >= 5


def test_unsafe_outputs_has_probes():
    attack = UnsafeOutputsAttack()
    assert len(attack.probes()) >= 5


def test_retrieval_poisoning_has_probes():
    attack = RetrievalPoisoningAttack()
    assert len(attack.probes()) >= 5


# ─── Probe schema validation ──────────────────────────────────────────────────

@pytest.mark.parametrize("attack_class", [
    PromptInjectionAttack,
    JailbreakAttack,
    DataLeakageAttack,
    ToolAbuseAttack,
    UnsafeOutputsAttack,
    RetrievalPoisoningAttack,
])
def test_probe_schema(attack_class):
    attack = attack_class()
    for probe in attack.probes():
        assert "name" in probe, "probe must have a name"
        assert "payload" in probe, "probe must have a payload"
        assert isinstance(probe["name"], str)
        assert isinstance(probe["payload"], str)
        assert len(probe["payload"]) > 0


# ─── Category assignment ──────────────────────────────────────────────────────

def test_prompt_injection_category():
    assert PromptInjectionAttack().category == AttackCategory.PROMPT_INJECTION


def test_jailbreak_category():
    assert JailbreakAttack().category == AttackCategory.JAILBREAK


def test_data_leakage_category():
    assert DataLeakageAttack().category == AttackCategory.DATA_LEAKAGE


def test_tool_abuse_category():
    assert ToolAbuseAttack().category == AttackCategory.TOOL_ABUSE


def test_unsafe_outputs_category():
    assert UnsafeOutputsAttack().category == AttackCategory.UNSAFE_OUTPUTS


def test_retrieval_poisoning_category():
    assert RetrievalPoisoningAttack().category == AttackCategory.RETRIEVAL_POISONING


# ─── Run with mock target ─────────────────────────────────────────────────────

def test_attack_run_returns_results(refusing_target, scorer):
    attack = PromptInjectionAttack()
    attack.delay_seconds = 0  # skip sleep in tests

    results = attack.run(refusing_target, scorer)

    assert len(results) == len(attack.probes())
    for r in results:
        assert isinstance(r, AttackResult)
        assert r.category == AttackCategory.PROMPT_INJECTION
        assert 0.0 <= r.score <= 1.0
        assert r.severity in Severity


def test_refusing_target_passes(refusing_target, scorer):
    attack = JailbreakAttack()
    attack.delay_seconds = 0

    results = attack.run(refusing_target, scorer)

    passed = sum(1 for r in results if r.passed)
    assert passed > 0, "Refusing target should pass at least some jailbreak probes"


def test_compliant_target_fails(compliant_target, scorer):
    attack = JailbreakAttack()
    attack.delay_seconds = 0

    results = attack.run(compliant_target, scorer)

    failed = sum(1 for r in results if not r.passed)
    assert failed > 0, "Compliant target should fail at least some jailbreak probes"


def test_mock_target_records_calls(refusing_target, scorer):
    attack = PromptInjectionAttack()
    attack.delay_seconds = 0

    attack.run(refusing_target, scorer)

    assert len(refusing_target.call_log) == len(attack.probes())


def test_result_payload_matches_probe(refusing_target, scorer):
    attack = DataLeakageAttack()
    attack.delay_seconds = 0
    probes = attack.probes()

    results = attack.run(refusing_target, scorer)

    payloads_in_results = {r.payload for r in results}
    payloads_in_probes = {p["payload"] for p in probes}
    assert payloads_in_results == payloads_in_probes
