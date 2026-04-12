"""Runner — orchestrates attack suites against a target and collects results."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from red_team.attacks.base import BaseAttack
from red_team.core.models import AttackCategory, ScanReport, Severity

if TYPE_CHECKING:
    from red_team.core.scorer import HeuristicScorer, LLMScorer
    from red_team.core.target import Target


_SEVERITY_COLOR = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.PASS: "green",
}

console = Console()


class Runner:
    """
    Orchestrates one or more attack modules against a target.

    Usage:
        runner = Runner(target, scorer, attacks=[...])
        report = runner.run()
    """

    def __init__(
        self,
        target: "Target",
        scorer: "LLMScorer | HeuristicScorer",
        attacks: list[BaseAttack],
        verbose: bool = True,
    ) -> None:
        self._target = target
        self._scorer = scorer
        self._attacks = attacks
        self._verbose = verbose

    def run(self) -> ScanReport:
        started_at = datetime.now(timezone.utc)
        all_results = []

        total_probes = sum(len(a.probes()) for a in self._attacks)

        if self._verbose:
            console.rule("[bold blue]Red Team Scan Starting")
            console.print(f"Target: [bold]{self._target.name}[/bold]")
            console.print(f"Attack modules: {len(self._attacks)}")
            console.print(f"Total probes: {total_probes}\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            disable=not self._verbose,
        ) as progress:
            task = progress.add_task("Running attacks...", total=total_probes)

            for attack in self._attacks:
                category_label = attack.category.value.replace("_", " ").title()
                progress.update(task, description=f"[cyan]{category_label}[/cyan]")

                results = attack.run(self._target, self._scorer)
                all_results.extend(results)

                progress.advance(task, len(results))

        finished_at = datetime.now(timezone.utc)

        report = ScanReport(
            scan_id=str(uuid.uuid4()),
            target_name=self._target.name,
            target_description=self._target.description,
            started_at=started_at,
            finished_at=finished_at,
            results=all_results,
        )
        report.compute_summaries()

        if self._verbose:
            self._print_summary(report)

        return report

    def _print_summary(self, report: ScanReport) -> None:
        console.print()
        console.rule("[bold blue]Scan Complete")

        # Overall stats
        pass_rate_pct = f"{report.overall_pass_rate * 100:.1f}%"
        color = "green" if report.overall_pass_rate >= 0.8 else "red"
        console.print(
            f"\nOverall pass rate: [{color}]{pass_rate_pct}[/{color}] "
            f"({report.total_passed}/{report.total_probes} probes passed)\n"
        )

        # Per-category table
        table = Table(title="Results by Category", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Probes", justify="right")
        table.add_column("Passed", justify="right")
        table.add_column("Failed", justify="right")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("High", justify="right", style="orange3")
        table.add_column("Pass Rate", justify="right")

        for s in sorted(report.category_summaries, key=lambda x: x.pass_rate):
            rate_str = f"{s.pass_rate * 100:.0f}%"
            rate_color = "green" if s.pass_rate >= 0.8 else "red"
            table.add_row(
                s.category.value.replace("_", " ").title(),
                str(s.total),
                str(s.passed),
                str(s.failed),
                str(s.critical),
                str(s.high),
                f"[{rate_color}]{rate_str}[/{rate_color}]",
            )

        console.print(table)

        # Flag criticals
        criticals = [r for r in report.results if r.severity == Severity.CRITICAL]
        if criticals:
            console.print(f"\n[red bold]CRITICAL findings ({len(criticals)}):[/red bold]")
            for r in criticals:
                console.print(f"  • [{r.category.value}] {r.probe_name}: {r.reasoning}")
