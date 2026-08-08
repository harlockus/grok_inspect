"""Process and LOLBin heuristic rules."""

from __future__ import annotations

from grok_inspect.models import Finding, ScanBundle, Severity


def apply(bundle: ScanBundle) -> list[Finding]:
    out: list[Finding] = []
    os_family = bundle.host.get("os_family")
    proc = bundle.evidence_for("process")
    suspicious = proc.get("suspicious_sample") or proc.get("processes") or []

    for p in suspicious:
        if not isinstance(p, dict):
            continue
        tags = p.get("tags") or []
        if "encoded_powershell" in tags:
            out.append(
                Finding(
                    id="process.encoded_powershell",
                    title="Encoded PowerShell command line",
                    summary=f"Process {p.get('name')} pid={p.get('pid')} uses encoded PowerShell",
                    severity=Severity.HIGH,
                    category="process",
                    evidence={
                        "pid": p.get("pid"),
                        "name": p.get("name"),
                        "cmdline": (p.get("cmdline") or "")[:200],
                    },
                    confidence=0.85,
                    remediation_hint="Investigate parent process and decode offline in a sandbox",
                    os=os_family,
                )
            )
        if "curl_pipe_shell" in tags:
            out.append(
                Finding(
                    id="process.curl_pipe_shell",
                    title="Download-and-pipe-to-shell pattern",
                    summary=f"Process {p.get('name')} cmdline suggests curl|sh style execution",
                    severity=Severity.HIGH,
                    category="process",
                    evidence={
                        "pid": p.get("pid"),
                        "name": p.get("name"),
                        "cmdline": (p.get("cmdline") or "")[:200],
                    },
                    confidence=0.8,
                    remediation_hint="Terminate if untrusted; audit how it was launched",
                    os=os_family,
                )
            )
        if p.get("masquerade"):
            out.append(
                Finding(
                    id="process.masquerade_path",
                    title="System process name from non-system path",
                    summary=f"{p.get('name')} running from unexpected path {p.get('path')}",
                    severity=Severity.HIGH,
                    category="process",
                    evidence={
                        "pid": p.get("pid"),
                        "name": p.get("name"),
                        "path": p.get("path"),
                    },
                    confidence=0.8,
                    remediation_hint="Compare with legitimate binary location; quarantine if fake",
                    os=os_family,
                )
            )
        if "script_obfuscation" in tags and "encoded_powershell" not in tags:
            out.append(
                Finding(
                    id="process.script_obfuscation",
                    title="Obfuscated script indicators in command line",
                    summary=f"Process {p.get('name')} shows base64/IEX-style patterns",
                    severity=Severity.MEDIUM,
                    category="process",
                    evidence={
                        "pid": p.get("pid"),
                        "name": p.get("name"),
                        "cmdline": (p.get("cmdline") or "")[:200],
                    },
                    confidence=0.7,
                    remediation_hint="Review script origin and parent process",
                    os=os_family,
                )
            )

    return out
