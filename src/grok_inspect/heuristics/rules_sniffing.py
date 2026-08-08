"""Sniffing-related heuristic rules."""

from __future__ import annotations

from grok_inspect.models import Finding, ScanBundle, Severity


def apply(bundle: ScanBundle) -> list[Finding]:
    out: list[Finding] = []
    os_family = bundle.host.get("os_family")
    sniff = bundle.evidence_for("sniff_surface")
    net = bundle.evidence_for("network")

    promisc = list(sniff.get("promisc_interfaces") or []) + list(
        net.get("promisc_interfaces") or []
    )
    for iface in dict.fromkeys(promisc):
        out.append(
            Finding(
                id="sniff.promisc_iface",
                title="Interface in promiscuous mode",
                summary=f"Interface {iface} appears promiscuous (strong sniffing signal)",
                severity=Severity.HIGH,
                category="sniffing",
                evidence={"iface": iface},
                confidence=0.85,
                remediation_hint="Identify process using the interface; disable promisc if unexpected",
                os=os_family,
            )
        )

    for proc in sniff.get("capture_processes") or []:
        name = proc.get("name") if isinstance(proc, dict) else str(proc)
        out.append(
            Finding(
                id="sniff.capture_process",
                title="Packet capture process running",
                summary=f"Capture-related process observed: {name}",
                severity=Severity.MEDIUM,
                category="sniffing",
                evidence={"process": proc},
                confidence=0.8,
                remediation_hint="Verify this is authorized troubleshooting or security tooling",
                os=os_family,
            )
        )

    for b in sniff.get("capture_binaries_in_path") or []:
        out.append(
            Finding(
                id="sniff.capture_binary_installed",
                title="Capture tool installed",
                summary=f"Capture-related binary on PATH: {b.get('name') if isinstance(b, dict) else b}",
                severity=Severity.INFO,
                category="sniffing",
                evidence={"binary": b},
                confidence=0.7,
                remediation_hint="Expected on admin workstations; remove if unauthorized",
                os=os_family,
            )
        )

    bpf = sniff.get("bpf_devices") or []
    if bpf and len(bpf) > 0:
        out.append(
            Finding(
                id="sniff.bpf_devices",
                title="BPF capture devices present",
                summary=f"Found {len(bpf)} BPF device(s) under /dev",
                severity=Severity.INFO,
                category="sniffing",
                evidence={"bpf_devices": bpf[:10]},
                confidence=0.6,
                remediation_hint="Normal on macOS/BSD when capture stack is available",
                os=os_family,
            )
        )

    return out
