"""JSON report generation for CI/CD integration."""

from __future__ import annotations

import json
from pathlib import Path

from red_team.core.models import ScanReport


class JsonReporter:
    def render(self, report: ScanReport) -> str:
        return report.model_dump_json(indent=2)

    def save(self, report: ScanReport, output_path: str | Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.render(report), encoding="utf-8")
        return output_path

    def to_ci_summary(self, report: ScanReport) -> dict:
        """Compact summary suitable for CI/CD status checks."""
        return {
            "scan_id": report.scan_id,
            "target": report.target_name,
            "pass_rate": round(report.overall_pass_rate, 4),
            "total": report.total_probes,
            "passed": report.total_passed,
            "failed": report.total_failed,
            "critical": sum(1 for r in report.results if r.severity.value == "critical"),
            "high": sum(1 for r in report.results if r.severity.value == "high"),
            "ok": report.total_failed == 0,
            "categories": {
                s.category.value: {
                    "pass_rate": round(s.pass_rate, 4),
                    "critical": s.critical,
                    "high": s.high,
                }
                for s in report.category_summaries
            },
        }
