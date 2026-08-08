"""Accounts and remote access collector."""

from __future__ import annotations

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd


def collect_accounts(ctx: CollectorContext) -> dict:
    family = ctx.os_family
    evidence: dict = {}
    limited = False

    if family in {"darwin", "linux"}:
        rc, out, _ = run_cmd(["who"], timeout=10)
        evidence["who"] = out.strip().splitlines()[:20] if rc == 0 else []
        rc, out, _ = run_cmd(["last", "-n", "10"], timeout=10)
        if rc == 0:
            evidence["last_logons"] = out.strip().splitlines()[:15]
        else:
            limited = True
        # ssh listening
        rc, out, _ = run_cmd(["lsof", "-nP", "-iTCP:22", "-sTCP:LISTEN"], timeout=10)
        if rc != 0 and family == "linux":
            rc, out, _ = run_cmd(["ss", "-lptn", "sport = :22"], timeout=10)
        evidence["ssh_listening"] = rc == 0 and bool(out.strip())
        if family == "darwin":
            rc, out, _ = run_cmd(["dscl", ".", "-list", "/Users"], timeout=15)
            if rc == 0:
                users = [
                    u.strip()
                    for u in out.splitlines()
                    if u.strip() and not u.startswith("_")
                ]
                evidence["users_sample"] = users[:40]
            else:
                limited = True
        else:
            try:
                from pathlib import Path

                text = Path("/etc/passwd").read_text(
                    encoding="utf-8", errors="replace"
                )
                users = []
                for ln in text.splitlines()[:500]:
                    parts = ln.split(":")
                    if len(parts) >= 3:
                        try:
                            uid = int(parts[2])
                        except ValueError:
                            continue
                        if uid >= 1000 or parts[0] == "root":
                            users.append(parts[0])
                evidence["users_sample"] = users[:40]
            except OSError:
                limited = True

    elif family == "windows":
        rc, out, _ = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-LocalUser | Select-Object Name,Enabled,LastLogon | ConvertTo-Json -Compress",
            ],
            timeout=30,
        )
        if rc == 0:
            evidence["users_json"] = out.strip()[:4000]
        else:
            limited = True
        rc, out, _ = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-NetTCPConnection -State Listen -LocalPort 22,3389 -ErrorAction SilentlyContinue | Measure-Object).Count",
            ],
            timeout=20,
        )
        evidence["ssh_or_rdp_listen_count"] = out.strip() if rc == 0 else "unknown"
    else:
        return {"_status": "skipped"}

    evidence["_status"] = "limited" if limited else "full"
    return evidence
