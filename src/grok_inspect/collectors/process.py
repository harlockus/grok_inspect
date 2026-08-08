"""Process inventory and LOLBin pattern collector."""

from __future__ import annotations

import re
from pathlib import Path

from grok_inspect.collectors.base import CollectorContext
from grok_inspect.collectors.subprocess_util import run_cmd

_ENCODED_PS = re.compile(
    r"(?i)powershell.*-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}"
)
_CURL_PIPE = re.compile(r"(?i)(curl|wget).*\|\s*(sh|bash|powershell)")
_MSHTA = re.compile(r"(?i)\bmshta\b")
_OSASCRIPT = re.compile(r"(?i)\bosascript\b.*-e")


def looks_like_encoded_powershell(cmdline: str) -> bool:
    return bool(_ENCODED_PS.search(cmdline or ""))


def classify_cmdline(cmdline: str) -> list[str]:
    tags: list[str] = []
    c = cmdline or ""
    if looks_like_encoded_powershell(c):
        tags.append("encoded_powershell")
    if _CURL_PIPE.search(c):
        tags.append("curl_pipe_shell")
    if _MSHTA.search(c):
        tags.append("mshta")
    if _OSASCRIPT.search(c):
        tags.append("osascript_eval")
    if re.search(r"(?i)frombase64string|invoke-expression|\biex\b", c):
        tags.append("script_obfuscation")
    return tags


def _system_prefixes(os_family: str) -> tuple[str, ...]:
    if os_family == "darwin":
        return ("/System/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/Library/")
    if os_family == "linux":
        return ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/lib/", "/usr/lib/")
    if os_family == "windows":
        return (
            r"c:\windows\system32",
            r"c:\windows\syswow64",
            r"c:\program files",
            r"c:\program files (x86)",
        )
    return ()


def _masquerade(name: str, path: str, os_family: str) -> bool:
    if not path or not name:
        return False
    system_names = {
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "explorer.exe",
        "csrss.exe",
        "launchd",
        "kernel_task",
        "systemd",
    }
    base = Path(name).name.lower()
    if base not in system_names and base.rstrip(".exe") not in {
        n.rstrip(".exe") for n in system_names
    }:
        return False
    pl = path.lower()
    return not any(pl.startswith(p.lower()) for p in _system_prefixes(os_family))


def collect_process(ctx: CollectorContext) -> dict:
    family = ctx.os_family
    processes: list[dict] = []
    limited = False

    if family in {"darwin", "linux"}:
        rc, out, err = run_cmd(
            ["ps", "-axo", "pid=,ppid=,user=,comm=,args="], timeout=30
        )
        if rc != 0:
            return {
                "_status": "error" if rc else "limited",
                "_detail": err[:200],
                "processes": [],
            }
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split(None, 4)
            if len(parts) < 4:
                continue
            pid, ppid, user, comm = parts[0], parts[1], parts[2], parts[3]
            args = parts[4] if len(parts) > 4 else comm
            path = comm
            entry = {
                "pid": pid,
                "ppid": ppid,
                "user": user,
                "name": Path(comm).name,
                "path": path[:300],
                "cmdline": (args or "")[:500],
                "tags": classify_cmdline(args or ""),
                "masquerade": _masquerade(Path(comm).name, path, family),
            }
            processes.append(entry)
            if len(processes) >= 400:
                limited = True
                break
    elif family == "windows":
        ps = (
            "Get-CimInstance Win32_Process | "
            "Select-Object -First 400 ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
            "ConvertTo-Json -Compress"
        )
        rc, out, err = run_cmd(
            ["powershell", "-NoProfile", "-Command", ps], timeout=45
        )
        if rc != 0 or not out.strip():
            limited = True
            return {
                "_status": "limited",
                "_detail": (err or "process enumeration failed")[:200],
                "processes": [],
            }
        # Keep raw JSON snippet; also try light parse without full json if array
        evidence_raw = out.strip()[:100_000]
        import json

        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for item in data or []:
                name = str(item.get("Name") or "")
                path = str(item.get("ExecutablePath") or "")
                cmd = str(item.get("CommandLine") or "")
                processes.append(
                    {
                        "pid": item.get("ProcessId"),
                        "ppid": item.get("ParentProcessId"),
                        "name": name,
                        "path": path[:300],
                        "cmdline": cmd[:500],
                        "tags": classify_cmdline(cmd),
                        "masquerade": _masquerade(name, path, family),
                    }
                )
        except json.JSONDecodeError:
            limited = True
            return {
                "_status": "limited",
                "processes_json": evidence_raw[:8000],
            }
    else:
        return {"_status": "skipped", "processes": []}

    tagged = [p for p in processes if p.get("tags") or p.get("masquerade")]
    return {
        "processes": processes[:400],
        "suspicious_sample": tagged[:50],
        "process_count": len(processes),
        "_status": "limited" if limited else "full",
    }
