"""Core data models for the red team framework."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    PASS = "pass"


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_LEAKAGE = "data_leakage"
    TOOL_ABUSE = "tool_abuse"
    UNSAFE_OUTPUTS = "unsafe_outputs"
    RETRIEVAL_POISONING = "retrieval_poisoning"


class AttackResult(BaseModel):
    attack_id: str
    category: AttackCategory
    probe_name: str
    payload: str
    response: str
    severity: Severity
    passed: bool  # True = target resisted the attack
    score: float = Field(ge=0.0, le=1.0)  # 0 = fully vulnerable, 1 = fully safe
    reasoning: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CategorySummary(BaseModel):
    category: AttackCategory
    total: int
    passed: int
    failed: int
    critical: int
    high: int
    medium: int
    low: int
    pass_rate: float


class ScanReport(BaseModel):
    scan_id: str
    target_name: str
    target_description: str
    started_at: datetime
    finished_at: datetime
    results: list[AttackResult]
    category_summaries: list[CategorySummary] = Field(default_factory=list)
    overall_pass_rate: float = 0.0
    total_probes: int = 0
    total_passed: int = 0
    total_failed: int = 0

    def compute_summaries(self) -> None:
        """Populate derived summary fields from results."""
        self.total_probes = len(self.results)
        self.total_passed = sum(1 for r in self.results if r.passed)
        self.total_failed = self.total_probes - self.total_passed
        self.overall_pass_rate = (
            self.total_passed / self.total_probes if self.total_probes else 0.0
        )

        by_category: dict[AttackCategory, list[AttackResult]] = {}
        for r in self.results:
            by_category.setdefault(r.category, []).append(r)

        self.category_summaries = []
        for cat, items in by_category.items():
            self.category_summaries.append(
                CategorySummary(
                    category=cat,
                    total=len(items),
                    passed=sum(1 for i in items if i.passed),
                    failed=sum(1 for i in items if not i.passed),
                    critical=sum(1 for i in items if i.severity == Severity.CRITICAL),
                    high=sum(1 for i in items if i.severity == Severity.HIGH),
                    medium=sum(1 for i in items if i.severity == Severity.MEDIUM),
                    low=sum(1 for i in items if i.severity == Severity.LOW),
                    pass_rate=sum(1 for i in items if i.passed) / len(items),
                )
            )
