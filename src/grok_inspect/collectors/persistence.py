"""Persistence mechanism collector."""

from __future__ import annotations

import os
from pathlib import Path

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd


def _list_plist_dir(d: Path, limit: int = 40) -> list[dict]:
    items: list[dict] = []
    if not d.is_dir():
        return items
    try:
        for p in sorted(d.iterdir())[:limit]:
            if p.suffix == ".plist" or p.is_file():
                try:
                    st = p.stat()
                    mtime = st.st_mtime
                except OSError:
                    mtime = None
                items.append({"path": str(p)[:400], "mtime": mtime})
    except OSError:
        pass
    return items


def collect_persistence(ctx: CollectorContext) -> dict:
    family = ctx.os_family
    items: list[dict] = []
    limited = False

    if family == "darwin":
        home = Path.home()
        for d in (
            home / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
            Path("/System/Library/LaunchDaemons"),
        ):
            found = _list_plist_dir(d)
            for f in found:
                f["kind"] = "launchd"
                f["dir"] = str(d)
            items.extend(found)
        rc, out, _ = run_cmd(["crontab", "-l"], timeout=10)
        if rc == 0 and out.strip():
            items.append(
                {
                    "kind": "crontab",
                    "path": "user_crontab",
                    "content_preview": out.strip()[:500],
                }
            )
    elif family == "linux":
        home = Path.home()
        for d in (
            home / ".config" / "systemd" / "user",
            Path("/etc/systemd/system"),
            home / ".config" / "autostart",
        ):
            if d.is_dir():
                try:
                    for p in sorted(d.iterdir())[:40]:
                        items.append({"kind": "unit_or_autostart", "path": str(p)[:400]})
                except OSError:
                    limited = True
        preload = Path("/etc/ld.so.preload")
        if preload.is_file():
            try:
                content = preload.read_text(encoding="utf-8", errors="replace")[:500]
                items.append(
                    {
                        "kind": "ld_so_preload",
                        "path": str(preload),
                        "content_preview": content,
                    }
                )
            except OSError:
                limited = True
        rc, out, _ = run_cmd(["crontab", "-l"], timeout=10)
        if rc == 0 and out.strip():
            items.append(
                {
                    "kind": "crontab",
                    "path": "user_crontab",
                    "content_preview": out.strip()[:500],
                }
            )
    elif family == "windows":
        for root_key, sub in (
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ):
            rc, out, _ = run_cmd(
                ["reg", "query", f"{root_key}\\{sub}"], timeout=15
            )
            if rc == 0 and out.strip():
                items.append(
                    {
                        "kind": "registry_run",
                        "path": f"{root_key}\\{sub}",
                        "content_preview": out.strip()[:800],
                    }
                )
            else:
                limited = True
        startup = (
            Path(os.environ.get("APPDATA", ""))
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "Startup"
        )
        if startup.is_dir():
            try:
                for p in sorted(startup.iterdir())[:30]:
                    items.append({"kind": "startup_folder", "path": str(p)[:400]})
            except OSError:
                limited = True
    else:
        return {"_status": "skipped", "items": []}

    # Flag temp/downloads-looking persistence
    risky = []
    for it in items:
        blob = (it.get("path") or "") + " " + (it.get("content_preview") or "")
        low = blob.lower()
        if any(
            x in low
            for x in (
                "/tmp/",
                "\\temp\\",
                "downloads",
                "appdata\\local\\temp",
                "/var/tmp",
            )
        ):
            risky.append(it)

    return {
        "items": items[:120],
        "risky_sample": risky[:30],
        "count": len(items),
        "_status": "limited" if limited else "full",
    }
