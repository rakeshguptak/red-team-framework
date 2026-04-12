"""Base attack class — all attack modules inherit from this."""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from red_team.core.models import AttackCategory, AttackResult, Severity

if TYPE_CHECKING:
    from red_team.core.scorer import HeuristicScorer, LLMScorer
    from red_team.core.target import Target


class BaseAttack(ABC):
    """
    Abstract base for all attack modules.

    Subclasses define a list of probes. The run() method fires each probe
    against the target, scores the response, and returns AttackResult objects.
    """

    category: AttackCategory
    delay_seconds: float = 0.5  # throttle between probes

    @abstractmethod
    def probes(self) -> list[dict[str, Any]]:
        """
        Return a list of probe descriptors.
        Each dict must have: 'name' (str), 'payload' (str).
        Optional: 'metadata' (dict).
        """

    def run(
        self,
        target: "Target",
        scorer: "LLMScorer | HeuristicScorer",
    ) -> list[AttackResult]:
        results: list[AttackResult] = []
        for probe in self.probes():
            payload = probe["payload"]
            response = target.query(payload)

            verdict = scorer.score(self.category, payload, response)

            results.append(
                AttackResult(
                    attack_id=str(uuid.uuid4()),
                    category=self.category,
                    probe_name=probe["name"],
                    payload=payload,
                    response=response,
                    severity=verdict["severity"],
                    passed=verdict["passed"],
                    score=verdict["score"],
                    reasoning=verdict["reasoning"],
                    metadata=probe.get("metadata", {}),
                )
            )
            if self.delay_seconds > 0:
                time.sleep(self.delay_seconds)
        return results
