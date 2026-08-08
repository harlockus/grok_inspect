"""USB / peripheral hints (best-effort, low confidence)."""

from __future__ import annotations

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd


def collect_peripheral(ctx: CollectorContext) -> dict:
    family = ctx.os_family
    if family == "darwin":
        rc, out, _ = run_cmd(["system_profiler", "SPUSBDataType"], timeout=40)
        if rc != 0:
            return {"_status": "limited", "_detail": "system_profiler failed", "usb_hint": []}
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()][:60]
        return {"usb_hint": lines, "_status": "full"}
    if family == "linux":
        rc, out, _ = run_cmd(["lsusb"], timeout=15)
        if rc != 0:
            return {"_status": "skipped", "_detail": "lsusb not available", "usb_hint": []}
        return {
            "usb_hint": [ln.strip() for ln in out.splitlines() if ln.strip()][:40],
            "_status": "full",
        }
    if family == "windows":
        rc, out, _ = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | "
                "Select-Object -First 30 FriendlyName,Status | ConvertTo-Json -Compress",
            ],
            timeout=30,
        )
        if rc != 0:
            return {"_status": "limited", "usb_hint": []}
        return {"usb_hint": [out.strip()[:4000]], "_status": "full"}
    return {"_status": "skipped", "usb_hint": []}
