"""Packet capture / MITM / sniffing surface collector."""

from __future__ import annotations

import os
from pathlib import Path

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd

CAPTURE_PROCESS_NAMES = {
    "tcpdump",
    "tshark",
    "dumpcap",
    "wireshark",
    "mitmproxy",
    "mitmdump",
    "charles",
    "fiddler",
    "bettercap",
    "ettercap",
    "rawcap",
    "npcap",
    "windump",
}


def match_capture_processes(process_names: list[str]) -> list[str]:
    lower_targets = {p.lower() for p in CAPTURE_PROCESS_NAMES}
    hits: set[str] = set()
    for n in process_names:
        nl = n.lower()
        base = Path(nl).name
        if base in lower_targets or any(t in nl for t in lower_targets):
            hits.add(n)
    return sorted(hits)


def _list_process_names(ctx: CollectorContext) -> list[str]:
    family = ctx.os_family
    names: list[str] = []
    if family in {"darwin", "linux"}:
        rc, out, _ = run_cmd(["ps", "-axo", "comm="], timeout=20)
        if rc == 0:
            for ln in out.splitlines():
                name = ln.strip()
                if name:
                    names.append(Path(name).name)
    elif family == "windows":
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
            names = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return names


def collect_sniff_surface(ctx: CollectorContext) -> dict:
    evidence: dict = {}
    limited = False
    names = _list_process_names(ctx)
    if not names:
        limited = True
    matched = match_capture_processes(names)
    evidence["capture_processes"] = [{"name": n} for n in matched]
    evidence["process_count_scanned"] = len(names)

    # Path presence for common tools
    path_bins = []
    for cand in ("tcpdump", "tshark", "dumpcap", "wireshark", "mitmproxy"):
        rc, out, _ = run_cmd(["which", cand] if ctx.os_family != "windows" else ["where", cand], timeout=5)
        if ctx.os_family == "windows":
            rc, out, _ = run_cmd(
                ["powershell", "-NoProfile", "-Command", f"Get-Command {cand} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source"],
                timeout=10,
            )
        if rc == 0 and out.strip():
            path_bins.append({"name": cand, "path": out.strip().splitlines()[0][:300]})
    evidence["capture_binaries_in_path"] = path_bins

    if ctx.os_family == "darwin":
        bpf = list(Path("/dev").glob("bpf*")) if Path("/dev").is_dir() else []
        evidence["bpf_devices"] = [str(p) for p in bpf[:20]]
        # Reuse promisc from ifconfig if needed
        rc, out, _ = run_cmd(["ifconfig"], timeout=15)
        promisc = []
        current = None
        if rc == 0:
            for ln in out.splitlines():
                if ":" in ln and not ln.startswith("\t") and not ln.startswith(" "):
                    current = ln.split(":")[0]
                if current and "PROMISC" in ln.upper():
                    promisc.append(current)
        evidence["promisc_interfaces"] = list(dict.fromkeys(promisc))
    elif ctx.os_family == "linux":
        rc, out, _ = run_cmd(["ip", "-o", "link"], timeout=15)
        promisc = []
        if rc == 0:
            for ln in out.splitlines():
                if "PROMISC" in ln.upper():
                    parts = ln.split(":", 2)
                    if len(parts) >= 2:
                        promisc.append(parts[1].strip().split("@")[0])
        evidence["promisc_interfaces"] = promisc
        evidence["bpf_devices"] = []
    else:
        evidence["promisc_interfaces"] = []
        # Npcap service hint
        rc, out, _ = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Service -Name npcap,npcap_wifi -ErrorAction SilentlyContinue | Select-Object Name,Status | ConvertTo-Json -Compress",
            ],
            timeout=15,
        )
        evidence["npcap_service"] = out.strip()[:500] if rc == 0 else "unknown"

    # Extra CA dirs (metadata only)
    ca_hints = []
    for p in (
        Path("/usr/local/share/ca-certificates"),
        Path.home() / "Library" / "Keychains",
        Path(os.environ.get("USERPROFILE", "")) / "AppData" / "LocalLow" / "Microsoft" / "CryptnetUrlCache",
    ):
        if p and str(p) != "." and p.exists():
            ca_hints.append(str(p))
    evidence["extra_root_cas_hint"] = ca_hints
    evidence["_status"] = "limited" if limited else "full"
    return evidence
