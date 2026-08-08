"""Bounded security/auth log samples."""

from __future__ import annotations

from pathlib import Path

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd


def collect_logs(ctx: CollectorContext) -> dict:
    family = ctx.os_family
    lines: list[str] = []
    limited = False

    if family == "darwin":
        rc, out, _ = run_cmd(
            [
                "log",
                "show",
                "--style",
                "syslog",
                "--predicate",
                'eventMessage CONTAINS "Authentication" OR eventMessage CONTAINS "sudo"',
                "--last",
                "1h",
            ],
            timeout=25,
        )
        if rc == 0:
            lines = [ln[:300] for ln in out.splitlines() if ln.strip()][:30]
        else:
            limited = True
    elif family == "linux":
        for path in (Path("/var/log/auth.log"), Path("/var/log/secure")):
            if path.is_file():
                try:
                    # read last portion
                    data = path.read_text(encoding="utf-8", errors="replace")
                    lines = [ln[:300] for ln in data.splitlines()[-40:] if ln.strip()][
                        :30
                    ]
                    break
                except OSError:
                    limited = True
        if not lines:
            rc, out, _ = run_cmd(
                ["journalctl", "-n", "30", "--no-pager", "-u", "sshd"],
                timeout=15,
            )
            if rc == 0:
                lines = [ln[:300] for ln in out.splitlines() if ln.strip()][:30]
            else:
                limited = True
    elif family == "windows":
        rc, out, _ = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-WinEvent -LogName Security -MaxEvents 20 -ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated,Id,Message | ForEach-Object { "
                "$_.TimeCreated.ToString() + ' ' + $_.Id + ' ' + ($_.Message -replace '\\s+',' ').Substring(0,[Math]::Min(120,$_.Message.Length)) }",
            ],
            timeout=40,
        )
        if rc == 0:
            lines = [ln[:300] for ln in out.splitlines() if ln.strip()][:30]
        else:
            limited = True
    else:
        return {"_status": "skipped", "auth_lines": []}

    return {
        "auth_lines": lines,
        "_status": "limited" if limited and not lines else ("limited" if limited else "full"),
    }
