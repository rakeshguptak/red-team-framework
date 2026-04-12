"""CLI entrypoint for the Red Team Framework."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

console = Console()


def _build_attacks(categories: list[str]):
    from red_team.attacks.data_leakage import DataLeakageAttack
    from red_team.attacks.jailbreak import JailbreakAttack
    from red_team.attacks.prompt_injection import PromptInjectionAttack
    from red_team.attacks.retrieval_poisoning import RetrievalPoisoningAttack
    from red_team.attacks.tool_abuse import ToolAbuseAttack
    from red_team.attacks.unsafe_outputs import UnsafeOutputsAttack

    all_attacks = {
        "prompt_injection": PromptInjectionAttack,
        "jailbreak": JailbreakAttack,
        "data_leakage": DataLeakageAttack,
        "tool_abuse": ToolAbuseAttack,
        "unsafe_outputs": UnsafeOutputsAttack,
        "retrieval_poisoning": RetrievalPoisoningAttack,
    }

    if "all" in categories:
        return [cls() for cls in all_attacks.values()]
    return [all_attacks[c]() for c in categories if c in all_attacks]


def _build_target(args):
    if args.target_type == "anthropic":
        from red_team.core.target import AnthropicTarget
        return AnthropicTarget(
            model=args.model,
            system_prompt=args.system_prompt or "You are a helpful assistant.",
            name=args.target_name or "claude-target",
        )
    if args.target_type == "openai":
        from red_team.core.target import OpenAITarget
        return OpenAITarget(
            model=args.model,
            system_prompt=args.system_prompt or "You are a helpful assistant.",
            name=args.target_name or "openai-target",
        )
    if args.target_type == "http":
        if not args.url:
            console.print("[red]--url is required for http target type[/red]")
            sys.exit(1)
        from red_team.core.target import HttpTarget
        return HttpTarget(url=args.url, name=args.target_name or "http-target")
    # mock (default)
    from red_team.core.target import MockTarget
    return MockTarget(default="I cannot help with that.")


def _build_scorer(args):
    if args.scorer == "llm":
        from red_team.core.scorer import LLMScorer
        return LLMScorer()
    from red_team.core.scorer import HeuristicScorer
    return HeuristicScorer()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Red Team Framework — automated LLM security testing",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--target-type",
        choices=["anthropic", "openai", "http", "mock"],
        default="mock",
        help="Type of target LLM (default: mock)",
    )
    parser.add_argument("--model", default=None, help="Model name for anthropic/openai targets")
    parser.add_argument("--system-prompt", default=None, help="System prompt for the target")
    parser.add_argument("--target-name", default=None, help="Display name for the target")
    parser.add_argument("--url", default=None, help="URL for http target type")
    parser.add_argument(
        "--categories",
        nargs="+",
        default=["all"],
        choices=[
            "all", "prompt_injection", "jailbreak", "data_leakage",
            "tool_abuse", "unsafe_outputs", "retrieval_poisoning",
        ],
        help="Attack categories to run (default: all)",
    )
    parser.add_argument(
        "--scorer",
        choices=["heuristic", "llm"],
        default="heuristic",
        help="Scoring method: heuristic (fast, offline) or llm (Anthropic judge, requires API key)",
    )
    parser.add_argument("--output-html", default="reports/report.html", help="HTML report output path")
    parser.add_argument("--output-json", default="reports/report.json", help="JSON report output path")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report")
    parser.add_argument("--no-json", action="store_true", help="Skip JSON report")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")

    args = parser.parse_args()

    target = _build_target(args)
    scorer = _build_scorer(args)
    attacks = _build_attacks(args.categories)

    if not attacks:
        console.print("[red]No attack modules selected.[/red]")
        sys.exit(1)

    from red_team.core.runner import Runner
    runner = Runner(target, scorer, attacks=attacks, verbose=not args.quiet)
    report = runner.run()

    if not args.no_html:
        from red_team.reporting.html_reporter import HtmlReporter
        path = HtmlReporter().save(report, args.output_html)
        console.print(f"\n[green]HTML report:[/green] {path}")

    if not args.no_json:
        from red_team.reporting.json_reporter import JsonReporter
        path = JsonReporter().save(report, args.output_json)
        console.print(f"[green]JSON report:[/green] {path}")

    # Exit non-zero if critical findings
    critical_count = sum(1 for r in report.results if r.severity.value == "critical")
    if critical_count > 0:
        console.print(f"\n[red bold]FAILED: {critical_count} critical finding(s)[/red bold]")
        sys.exit(1)

    console.print("\n[green bold]PASSED: No critical findings[/green bold]")


if __name__ == "__main__":
    main()
