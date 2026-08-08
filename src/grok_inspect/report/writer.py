"""Write full report pack + latest pointers (sanitized)."""

from __future__ import annotations

from pathlib import Path

from grok_inspect.models import ScanResult
from grok_inspect.report.html import to_html
from grok_inspect.report.json_report import to_json
from grok_inspect.report.markdown import to_markdown
from grok_inspect.security.paths import PathSecurityError, safe_report_dir
from grok_inspect.security.sanitize import sanitize_scan_result


def write_report_pack(result: ScanResult, out_dir: Path | str) -> dict[str, Path]:
    target = safe_report_dir(out_dir)
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PathSecurityError(f"Cannot create report directory: {target}") from exc

    safe = sanitize_scan_result(result)
    stamp = safe.finished_at.strftime("%Y%m%dT%H%M%SZ")
    # Filename only from timestamp — no user-controlled segments
    if not stamp.replace("T", "").replace("Z", "").isalnum():
        stamp = "report"
    base = f"grok-inspect-{stamp}"
    paths = {
        "json": target / f"{base}.json",
        "md": target / f"{base}.md",
        "html": target / f"{base}.html",
    }
    paths["json"].write_text(to_json(safe), encoding="utf-8")
    paths["md"].write_text(to_markdown(safe), encoding="utf-8")
    paths["html"].write_text(to_html(safe), encoding="utf-8")
    for ext, key in (("json", "json"), ("md", "md"), ("html", "html")):
        latest = target / f"latest.{ext}"
        latest.write_text(paths[key].read_text(encoding="utf-8"), encoding="utf-8")
    return paths
