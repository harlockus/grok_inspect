"""Rich terminal summary."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from grok_inspect.models import ScanResult, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_summary(result: ScanResult, out_dir: Path, console: Console | None = None) -> None:
    console = console or Console()
    console.print()
    console.rule("[bold]Grok Inspect — scan complete[/bold]")
    console.print(
        f"Host: [cyan]{result.host.get('hostname')}[/cyan]  "
        f"OS: {result.host.get('os_family')}  "
        f"Elevated: {'[green]yes[/green]' if result.elevated else '[yellow]no[/yellow]'}"
    )
    console.print(
        f"Max severity: [{_SEV_STYLE.get(result.score.max_severity, 'white')}]"
        f"{result.score.max_severity.value}[/]  "
        f"Open findings: {result.score.open_finding_count}"
    )
    if result.grok.available:
        risk = result.grok.risk_rating or "n/a"
        console.print(
            f"Grok: [green]ok[/green] model={result.grok.model_id} "
            f"effort={result.grok.reasoning_effort}  "
            f"risk=[bold]{risk}[/bold]"
        )
        if result.grok.executive_summary:
            console.print(
                f"[bold]Executive summary:[/bold] {result.grok.executive_summary[:500]}"
            )
        n_exec = len(result.grok.executive_actions or [])
        n_detail = len(result.grok.detailed_actions or [])
        if n_exec or n_detail:
            console.print(
                f"Actions: [cyan]{n_exec}[/cyan] executive · "
                f"[cyan]{n_detail}[/cyan] detailed technical"
            )
    else:
        console.print(
            f"Grok: [dim]unavailable[/dim] ({result.grok.error or 'skipped'})"
        )


    table = Table(title="Top findings", show_lines=False)
    table.add_column("Sev", style="bold")
    table.add_column("ID")
    table.add_column("Title")
    open_f = [f for f in result.findings if not f.acknowledged][:15]
    for f in open_f:
        table.add_row(
            f.severity.value,
            f.id,
            f.title[:60],
            style=_SEV_STYLE.get(f.severity),
        )
    if open_f:
        console.print(table)
    else:
        console.print("[green]No open findings.[/green]")

    console.print(f"\nReports written under: [bold]{out_dir}[/bold]")
    console.print("  latest.md / latest.json / latest.html")
    if not result.elevated:
        console.print(
            "[yellow]Tip:[/yellow] re-run elevated (sudo / Administrator) for full coverage"
        )
    console.print()
