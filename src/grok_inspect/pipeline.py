"""End-to-end scan orchestration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from rich.console import Console

from grok_inspect import __version__
from grok_inspect.agent.grok import analyze_with_grok
from grok_inspect.collectors.base import CollectorContext, run_collector
from grok_inspect.collectors.coverage import build_coverage
from grok_inspect.collectors.registry import COLLECTORS
from grok_inspect.config import Settings
from grok_inspect.heuristics.allowlist import Allowlist
from grok_inspect.heuristics.engine import run_heuristics
from grok_inspect.models import GrokAnalysis, ScanBundle, ScanResult, ScanScore, utcnow
from grok_inspect.platform import probe_host
from grok_inspect.report.writer import write_report_pack

ProgressFn = Callable[[str], None]


def run_scan(
    settings: Settings,
    *,
    use_grok: bool = True,
    out_dir: Path | None = None,
    allowlist_path: Path | None = None,
    verbose: bool = False,
    console: Console | None = None,
) -> ScanResult:
    console = console or Console(stderr=True)
    started = utcnow()
    host = probe_host()
    elevated = bool(host.get("elevated"))
    project_root = settings.project_root

    def log(msg: str) -> None:
        if verbose:
            console.print(f"[dim]{msg}[/dim]")

    results = []
    timeout = float(settings.scan.collector_timeout_sec)
    ctx = CollectorContext(
        host=host,
        timeout_sec=timeout,
        project_root=project_root,
    )

    for name, fn in COLLECTORS:
        log(f"collector:{name} …")
        # Refresh timeout on context per collector
        ctx.timeout_sec = timeout
        r = run_collector(name, fn, ctx)
        results.append(r)
        log(f"collector:{name} → {r.status.value}")

    coverage_entries, coverage_findings = build_coverage(
        results, elevated=elevated, os_family=str(host.get("os_family", ""))
    )

    bundle = ScanBundle(
        started_at=started,
        host=host,
        elevated=elevated,
        results=results,
    )

    allowlist = None
    if allowlist_path:
        allowlist = Allowlist.from_yaml(allowlist_path)

    findings = run_heuristics(bundle, allowlist=allowlist)
    findings = coverage_findings + findings
    findings.sort(key=lambda f: (-f.severity.rank, f.id))
    score = ScanScore.from_findings(findings)

    finished_partial = utcnow()
    result = ScanResult(
        tool_version=__version__,
        started_at=started,
        finished_at=finished_partial,
        host=host,
        elevated=elevated,
        coverage=coverage_entries,
        findings=findings,
        score=score,
        grok=GrokAnalysis(available=False, error="pending"),
        bundle_summary={
            "collectors": [
                {"name": r.name, "status": r.status.value, "error": r.error}
                for r in results
            ]
        },
    )

    if use_grok and settings.grok_available:
        log(
            f"grok: key {settings.api_key_status()}; "
            f"model={settings.model.id} reasoning_effort={settings.model.reasoning_effort}"
        )
        log("grok: analyzing …")
        home = os.path.expanduser("~")
        result.grok = analyze_with_grok(result, settings, home=home)
        log(
            "grok: "
            + (
                "ok"
                if result.grok.available
                else f"failed ({result.grok.error})"
            )
        )
    else:
        if not use_grok:
            reason = "disabled via --no-grok"
        else:
            reason = (
                f"XAI_API_KEY not set — add it to {settings.env_file or (settings.project_root / '.env')}"
            )
        result.grok = GrokAnalysis(available=False, error=reason)


    result.finished_at = utcnow()
    from grok_inspect.security.paths import safe_report_dir
    from grok_inspect.security.sanitize import sanitize_scan_result

    target = safe_report_dir(out_dir or (Path.cwd() / settings.reports.dir))
    write_report_pack(result, target)
    log(f"reports → {target}")
    # Return sanitized view (no raw_text / secrets in caller-held object)
    return sanitize_scan_result(result)

