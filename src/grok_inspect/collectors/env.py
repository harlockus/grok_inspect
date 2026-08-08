"""Environment and posture probe collector."""

from __future__ import annotations

import os

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd


def collect_env(ctx: CollectorContext) -> dict:
    proxy_keys = (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    )
    evidence: dict = {
        "host": dict(ctx.host),
        "proxy_env": {k: True for k in proxy_keys if os.environ.get(k)},
    }
    family = ctx.os_family
    if family == "darwin":
        rc, out, _ = run_cmd(["csrutil", "status"], timeout=10)
        evidence["sip_status"] = out.strip() if rc == 0 else "unknown"
        rc, out, _ = run_cmd(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            timeout=10,
        )
        evidence["firewall_hint"] = out.strip() if rc == 0 else "unknown"
    elif family == "linux":
        rc, out, _ = run_cmd(["getenforce"], timeout=5)
        if rc == 0:
            evidence["selinux"] = out.strip()
        rc, out, _ = run_cmd(["ufw", "status"], timeout=10)
        if rc == 0:
            evidence["firewall_hint"] = out.strip()[:200]
        else:
            rc, out, _ = run_cmd(["systemctl", "is-active", "firewalld"], timeout=10)
            evidence["firewall_hint"] = out.strip() if rc == 0 else "unknown"
    elif family == "windows":
        rc, out, _ = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress)",
            ],
            timeout=20,
        )
        evidence["firewall_hint"] = out.strip()[:500] if rc == 0 else "unknown"
    evidence["_status"] = "full"
    return evidence
