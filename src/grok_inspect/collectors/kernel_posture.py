"""Kernel / driver / security posture collector."""

from __future__ import annotations

from pathlib import Path

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd


def collect_kernel(ctx: CollectorContext) -> dict:
    family = ctx.os_family
    evidence: dict = {}
    limited = False

    if family == "darwin":
        rc, out, _ = run_cmd(["kmutil", "showloaded"], timeout=25)
        if rc == 0:
            evidence["kext_sample"] = out.splitlines()[:40]
        else:
            rc, out, _ = run_cmd(["kextstat"], timeout=20)
            if rc == 0:
                evidence["kext_sample"] = out.splitlines()[:40]
            else:
                limited = True
        rc, out, _ = run_cmd(["systemextensionsctl", "list"], timeout=15)
        if rc == 0:
            evidence["system_extensions"] = out.splitlines()[:40]
        docker_sock = Path("/var/run/docker.sock")
        evidence["docker_socket_exists"] = docker_sock.exists()
    elif family == "linux":
        rc, out, _ = run_cmd(["lsmod"], timeout=15)
        if rc == 0:
            evidence["modules_sample"] = out.splitlines()[:50]
        else:
            limited = True
        docker_sock = Path("/var/run/docker.sock")
        evidence["docker_socket_exists"] = docker_sock.exists()
        if docker_sock.exists():
            try:
                st = docker_sock.stat()
                evidence["docker_socket_mode"] = oct(st.st_mode & 0o777)
            except OSError:
                pass
    elif family == "windows":
        rc, out, _ = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-WindowsDriver -Online -ErrorAction SilentlyContinue | Select-Object -First 20 Driver,OriginalFileName | ConvertTo-Json -Compress",
            ],
            timeout=40,
        )
        if rc == 0 and out.strip():
            evidence["drivers_sample"] = out.strip()[:4000]
        else:
            limited = True
            # lighter fallback
            rc, out, _ = run_cmd(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 30 Name | ConvertTo-Json -Compress",
                ],
                timeout=30,
            )
            evidence["running_services_sample"] = out.strip()[:3000] if rc == 0 else ""
    else:
        return {"_status": "skipped"}

    evidence["_status"] = "limited" if limited else "full"
    return evidence
