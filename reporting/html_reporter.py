"""HTML report generation using Jinja2."""

from __future__ import annotations

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from red_team.core.models import ScanReport, Severity

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


class HtmlReporter:
    def __init__(self, template_dir: Path = _TEMPLATE_DIR) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
        )

    def render(self, report: ScanReport) -> str:
        template = self._env.get_template("report.html.j2")
        critical_count = sum(1 for r in report.results if r.severity == Severity.CRITICAL)
        high_count = sum(1 for r in report.results if r.severity == Severity.HIGH)
        return template.render(
            report=report,
            critical_count=critical_count,
            high_count=high_count,
        )

    def save(self, report: ScanReport, output_path: str | Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.render(report), encoding="utf-8")
        return output_path
