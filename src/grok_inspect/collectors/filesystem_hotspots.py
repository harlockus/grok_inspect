"""Targeted filesystem hotspot collector (not full-disk AV)."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd

EXEC_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".sh", ".ps1", ".bat", ".cmd", ""}


def collect_filesystem(ctx: CollectorContext) -> dict:
    family = ctx.os_family
    limited = False
    recent: list[dict] = []
    world_writable: list[str] = []
    suid_sample: list[str] = []
    now = time.time()
    window = 30 * 24 * 3600  # 30 days

    scan_dirs = [
        Path.home() / "Downloads",
        Path.home() / "Desktop",
        Path("/tmp"),
        Path("/var/tmp"),
        Path.home() / "AppData" / "Local" / "Temp",
        Path.home() / "Library" / "LaunchAgents",
    ]
    for d in scan_dirs:
        if not d.is_dir():
            continue
        try:
            for p in d.iterdir():
                try:
                    st = p.stat()
                except OSError:
                    continue
                if not p.is_file():
                    continue
                age_ok = (now - st.st_mtime) <= window
                looks_exec = (
                    p.suffix.lower() in EXEC_EXTS
                    or bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                )
                if age_ok and looks_exec:
                    recent.append(
                        {
                            "path": str(p)[:400],
                            "mtime": st.st_mtime,
                            "size": st.st_size,
                        }
                    )
                if len(recent) >= 50:
                    break
        except OSError:
            limited = True

    if family in {"darwin", "linux"}:
        # Sample SUID in /usr/bin (bounded)
        for base in (Path("/usr/bin"), Path("/usr/sbin"), Path("/bin")):
            if not base.is_dir():
                continue
            try:
                for p in list(base.iterdir())[:200]:
                    try:
                        st = p.stat()
                    except OSError:
                        continue
                    if st.st_mode & stat.S_ISUID:
                        suid_sample.append(str(p))
                    if len(suid_sample) >= 30:
                        break
            except OSError:
                limited = True
        # World-writable in /tmp
        tmp = Path("/tmp")
        if tmp.is_dir():
            try:
                for p in list(tmp.iterdir())[:100]:
                    try:
                        st = p.stat()
                        if st.st_mode & stat.S_IWOTH and p.is_file():
                            world_writable.append(str(p)[:400])
                    except OSError:
                        continue
                    if len(world_writable) >= 20:
                        break
            except OSError:
                limited = True

    # Browser extensions (paths only)
    ext_roots = [
        Path.home()
        / "Library"
        / "Application Support"
        / "Google"
        / "Chrome"
        / "Default"
        / "Extensions",
        Path.home()
        / "AppData"
        / "Local"
        / "Google"
        / "Chrome"
        / "User Data"
        / "Default"
        / "Extensions",
        Path.home() / ".config" / "google-chrome" / "Default" / "Extensions",
    ]
    extensions: list[str] = []
    for root in ext_roots:
        if root.is_dir():
            try:
                for p in sorted(root.iterdir())[:40]:
                    extensions.append(p.name)
            except OSError:
                limited = True

    return {
        "recent_exec_sample": recent[:50],
        "suid_sample": suid_sample[:30],
        "world_writable_hits": world_writable[:20],
        "browser_extension_ids": extensions[:40],
        "_status": "limited" if limited else "full",
    }
