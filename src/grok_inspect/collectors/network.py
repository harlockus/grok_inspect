"""Network surface collector."""

from __future__ import annotations

import os
import re
from pathlib import Path

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd


def _parse_hosts_file(path: Path) -> list[str]:
    suspicious: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return suspicious
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^(127\.|::1|fe80:|0\.0\.0\.0\s+broadcasthost)", line, re.I):
            continue
        if "localhost" in line.lower():
            continue
        suspicious.append(line[:200])
    return suspicious[:50]


def _collect_darwin(ctx: CollectorContext) -> dict:
    limited = False
    evidence: dict = {}
    rc, out, err = run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=25)
    if rc == 0:
        evidence["listeners_raw"] = [ln for ln in out.splitlines() if ln.strip()][:80]
    else:
        limited = True
        evidence["listeners_error"] = err[:200]
    rc, out, _ = run_cmd(["netstat", "-rn"], timeout=15)
    if rc == 0:
        evidence["routes_raw"] = [
            ln for ln in out.splitlines() if "default" in ln.lower()
        ][:20]
    rc, out, _ = run_cmd(["ifconfig"], timeout=15)
    if rc == 0:
        ifaces: list[str] = []
        promisc: list[str] = []
        current = None
        for ln in out.splitlines():
            m = re.match(r"^([a-zA-Z0-9]+):", ln)
            if m:
                current = m.group(1)
                ifaces.append(current)
            if current and "PROMISC" in ln.upper():
                promisc.append(current)
        evidence["interfaces"] = ifaces
        evidence["promisc_interfaces"] = promisc
    evidence["hosts_file_suspicious"] = _parse_hosts_file(Path("/etc/hosts"))
    rc, out, _ = run_cmd(["networksetup", "-getwebproxy", "Wi-Fi"], timeout=10)
    if rc == 0:
        evidence["proxy_wifi_web"] = out.strip()[:300]
    evidence["_status"] = "limited" if limited else "full"
    if limited:
        evidence["_detail"] = "Some network commands failed or partial"
    return evidence


def _collect_linux(ctx: CollectorContext) -> dict:
    limited = False
    evidence: dict = {}
    rc, out, err = run_cmd(["ss", "-lptn"], timeout=25)
    if rc != 0:
        rc, out, err = run_cmd(["ss", "-ltn"], timeout=25)
        limited = True
    if rc == 0:
        evidence["listeners_raw"] = out.splitlines()[:80]
    else:
        limited = True
        evidence["listeners_error"] = err[:200]
    rc, out, _ = run_cmd(["ss", "-tpn"], timeout=25)
    if rc == 0:
        evidence["connections_sample"] = out.splitlines()[:100]
    rc, out, _ = run_cmd(["ip", "-o", "link"], timeout=15)
    if rc == 0:
        ifaces: list[str] = []
        promisc: list[str] = []
        for ln in out.splitlines():
            parts = ln.split(":", 2)
            if len(parts) >= 2:
                name = parts[1].strip().split("@")[0]
                ifaces.append(name)
                if "PROMISC" in ln.upper():
                    promisc.append(name)
        evidence["interfaces"] = ifaces
        evidence["promisc_interfaces"] = promisc
    else:
        limited = True
    rc, out, _ = run_cmd(["ip", "route"], timeout=10)
    if rc == 0:
        evidence["routes_raw"] = [ln for ln in out.splitlines() if "default" in ln][:20]
    evidence["hosts_file_suspicious"] = _parse_hosts_file(Path("/etc/hosts"))
    evidence["_status"] = "limited" if limited else "full"
    return evidence


def _collect_windows(ctx: CollectorContext) -> dict:
    limited = False
    evidence: dict = {}
    ps = (
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object -First 80 LocalAddress,LocalPort,OwningProcess | "
        "ConvertTo-Json -Compress"
    )
    rc, out, err = run_cmd(
        ["powershell", "-NoProfile", "-Command", ps], timeout=40
    )
    if rc == 0 and out.strip():
        evidence["listeners_json"] = out.strip()[:8000]
    else:
        limited = True
        evidence["listeners_error"] = (err or "")[:200]
    ps2 = (
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
        "Select-Object -First 100 RemoteAddress,RemotePort,OwningProcess | "
        "ConvertTo-Json -Compress"
    )
    rc, out, _ = run_cmd(
        ["powershell", "-NoProfile", "-Command", ps2], timeout=40
    )
    if rc == 0 and out.strip():
        evidence["connections_json"] = out.strip()[:8000]
    hosts_path = (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "System32"
        / "drivers"
        / "etc"
        / "hosts"
    )
    evidence["hosts_file_suspicious"] = _parse_hosts_file(hosts_path)
    evidence["_status"] = "limited" if limited else "full"
    return evidence


def collect_network(ctx: CollectorContext) -> dict:
    family = ctx.os_family
    if family == "darwin":
        return _collect_darwin(ctx)
    if family == "linux":
        return _collect_linux(ctx)
    if family == "windows":
        return _collect_windows(ctx)
    return {"_status": "skipped", "_detail": f"unsupported os_family={family}"}
