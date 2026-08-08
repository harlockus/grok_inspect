"""Command-line interface for Grok Inspect."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from grok_inspect import __version__
from grok_inspect.config import load_settings
from grok_inspect.pipeline import run_scan
from grok_inspect.report.terminal import print_summary
from grok_inspect.security.paths import PathSecurityError, safe_report_dir
from grok_inspect.security.redact import redact_text
from grok_inspect.security.sanitize import clamp_timeout

app = typer.Typer(
    name="grok-inspect",
    help="Host sniffing/stealer inspection with Grok 4.5 (SpaceXAI xai-sdk).",
    add_completion=False,
    no_args_is_help=True,
)
console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"grok-inspect {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Grok Inspect — defensive host inspection agent."""


@app.command("version")
def version_cmd() -> None:
    """Print version."""
    typer.echo(f"grok-inspect {__version__}")


@app.command("doctor")
def doctor_cmd() -> None:
    """Check project root, .env, and API key loading (never prints the key)."""
    settings = load_settings()
    env_path = settings.env_file or (settings.project_root / ".env")
    console.print(f"[bold]grok-inspect[/bold] {__version__}")
    console.print(f"Project root: [cyan]{settings.project_root}[/cyan]")
    console.print(f"Config: {settings.project_root / 'config' / 'default.yaml'}")
    console.print(f".env path: [cyan]{env_path}[/cyan]")
    if env_path.is_file():
        console.print(".env file: [green]found[/green]")
    else:
        console.print(
            ".env file: [yellow]missing[/yellow] — copy .env.example → .env and set XAI_API_KEY"
        )
    console.print(
        f"Model: [cyan]{settings.model.id}[/cyan] "
        f"(reasoning_effort={settings.model.reasoning_effort})"
    )
    if settings.grok_available:
        console.print("XAI_API_KEY: [green]present[/green]")
        console.print(f"Source: {settings.api_key_status()}")
        prefix = settings.api_key[:4] if len(settings.api_key) >= 4 else "****"
        console.print(
            f"Key length: {len(settings.api_key)} chars "
            f"(prefix [dim]{prefix}…[/dim] only)"
        )
        console.print("[green]Grok analysis ready[/green] for `grok-inspect scan`")
        raise typer.Exit(0)
    console.print("XAI_API_KEY: [red]not configured[/red]")
    console.print(f"Expected location: [cyan]{env_path}[/cyan]")
    console.print(
        "Store the key only in the project .env file:\n"
        "  1. cp .env.example .env\n"
        "  2. Edit .env and set: XAI_API_KEY=xai-...\n"
        "  3. Re-run: grok-inspect doctor\n"
        "Never put the key in config/*.yaml or commit .env."
    )
    raise typer.Exit(1)


@app.command("scan")
def scan_cmd(
    out: Optional[Path] = typer.Option(
        None, "--out", help="Report directory (default: ./reports)"
    ),
    no_grok: bool = typer.Option(
        False, "--no-grok", help="Heuristics only (skip SpaceXAI API)"
    ),
    allowlist: Optional[Path] = typer.Option(
        None, "--allowlist", help="Allowlist YAML path"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Collector progress"),
    timeout: Optional[int] = typer.Option(
        None, "--timeout", help="Per-collector timeout seconds (5–300)"
    ),
) -> None:
    """Run a comprehensive host inspection scan."""
    settings = load_settings()
    if timeout is not None:
        settings.scan.collector_timeout_sec = clamp_timeout(timeout)
    try:
        out_dir = safe_report_dir(out or (Path.cwd() / settings.reports.dir))
    except PathSecurityError as exc:
        console.print(f"[red]Invalid --out path:[/red] {exc}")
        raise typer.Exit(2) from exc

    if verbose:
        console.print(f"[dim]API key: {settings.api_key_status()}[/dim]")
    if not no_grok and not settings.grok_available:
        console.print(
            "[yellow]Warning:[/yellow] No XAI_API_KEY in project .env — "
            "scan will run heuristics only. "
            "Run [bold]grok-inspect doctor[/bold] for setup help, or use --no-grok to silence this."
        )
    try:
        result = run_scan(
            settings,
            use_grok=not no_grok,
            out_dir=out_dir,
            allowlist_path=allowlist,
            verbose=verbose,
            console=console,
        )
    except PathSecurityError as exc:
        console.print(f"[red]Path security:[/red] {exc}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        console.print(
            f"[red]Scan failed:[/red] {redact_text(str(type(exc).__name__))}"
        )
        raise typer.Exit(2) from exc
    print_summary(result, out_dir, console=console)
    raise typer.Exit(result.exit_code())


if __name__ == "__main__":
    app()
