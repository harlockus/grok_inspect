"""Stealer / credential-risk indicators (metadata only)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd
from grok_inspect.security.paths import PathSecurityError
from grok_inspect.security.safe_io import load_yaml_file


def load_iocs(path: Path) -> dict[str, Any]:
    try:
        data = load_yaml_file(path, max_bytes=256_000)
    except (PathSecurityError, OSError, FileNotFoundError):
        return {
            "path_substrings": [],
            "process_names": [],
            "suspicious_cmdline_regex": [],
        }
    return data if isinstance(data, dict) else {}


def path_matches_ioc(path: str, iocs: dict[str, Any]) -> bool:
    low = (path or "").lower()
    for sub in iocs.get("path_substrings") or []:
        if str(sub).lower() in low:
            return True
    return False


def _browser_profile_dirs() -> list[str]:
    home = Path.home()
    candidates = [
        home / "Library" / "Application Support" / "Google" / "Chrome" / "Default",
        home / "Library" / "Application Support" / "Chromium" / "Default",
        home / "Library" / "Application Support" / "Firefox" / "Profiles",
        home / "Library" / "Application Support" / "Microsoft Edge" / "Default",
        home / ".config" / "google-chrome" / "Default",
        home / ".config" / "chromium" / "Default",
        home / ".mozilla" / "firefox",
        home / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default",
        home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
    ]
    return [str(p) for p in candidates if p.exists()]


def collect_stealer(ctx: CollectorContext) -> dict:
    root = Path(ctx.project_root) if ctx.project_root else Path.cwd()
    ioc_path = root / "data" / "stealer_iocs.yaml"
    iocs = load_iocs(ioc_path)
    path_hits: list[str] = []
    proc_hits: list[str] = []

    scan_dirs = [
        Path.home() / "Downloads",
        Path.home() / "Desktop",
        Path("/tmp"),
        Path.home() / "AppData" / "Local" / "Temp",
        Path.home() / "Library" / "Caches",
    ]
    for d in scan_dirs:
        if not d.is_dir():
            continue
        try:
            for p in d.iterdir():
                # Metadata only — never open file contents
                if path_matches_ioc(str(p), iocs):
                    path_hits.append(str(p)[:400])
                if len(path_hits) >= 30:
                    break
        except OSError:
            continue

    names: list[str] = []
    if ctx.os_family in {"darwin", "linux"}:
        rc, out, _ = run_cmd(["ps", "-axo", "comm="], timeout=20)
        if rc == 0:
            names = [Path(x.strip()).name for x in out.splitlines() if x.strip()]
    elif ctx.os_family == "windows":
        rc, out, _ = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Process | Select-Object -ExpandProperty ProcessName",
            ],
            timeout=30,
        )
        if rc == 0:
            names = [x.strip() for x in out.splitlines() if x.strip()]

    ioc_names = {str(n).lower() for n in (iocs.get("process_names") or [])}
    for n in names:
        if n.lower() in ioc_names or any(i in n.lower() for i in ioc_names if i):
            proc_hits.append(n)

    browser_profiles = _browser_profile_dirs()
    auth_keys = Path.home() / ".ssh" / "authorized_keys"
    auth_meta: dict[str, Any] = {"exists": auth_keys.is_file()}
    if auth_keys.is_file():
        try:
            st = auth_keys.stat()
            # Metadata + key count only — do not export public key material
            lines = [
                ln
                for ln in auth_keys.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            auth_meta["key_count"] = len(lines)
            auth_meta["mtime"] = st.st_mtime
            auth_meta["mode"] = oct(st.st_mode & 0o777)
        except OSError:
            auth_meta["error"] = "unreadable"

    return {
        "path_hits": path_hits,
        "process_hits": sorted(set(proc_hits)),
        "browser_profiles_present": browser_profiles,
        "authorized_keys": auth_meta,
        "ioc_version": iocs.get("version"),
        "_status": "full",
    }
