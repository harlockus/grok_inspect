"""Security posture heuristic rules."""

from __future__ import annotations

from grok_inspect.models import Finding, ScanBundle, Severity


def apply(bundle: ScanBundle) -> list[Finding]:
    out: list[Finding] = []
    os_family = bundle.host.get("os_family")
    env = bundle.evidence_for("env")
    kernel = bundle.evidence_for("kernel_posture")
    fs = bundle.evidence_for("filesystem_hotspots")

    sip = str(env.get("sip_status") or "")
    if sip and "disabled" in sip.lower():
        out.append(
            Finding(
                id="posture.sip_disabled",
                title="System Integrity Protection appears disabled",
                summary=sip[:200],
                severity=Severity.HIGH,
                category="posture",
                evidence={"sip_status": sip},
                confidence=0.85,
                remediation_hint="Re-enable SIP from recovery if unexpected",
                os=os_family,
            )
        )

    fw = str(env.get("firewall_hint") or "")
    if fw and any(
        x in fw.lower() for x in ("disabled", "off", "inactive", "false")
    ):
        out.append(
            Finding(
                id="posture.firewall_off",
                title="Host firewall may be disabled",
                summary=fw[:200],
                severity=Severity.MEDIUM,
                category="posture",
                evidence={"firewall_hint": fw[:300]},
                confidence=0.7,
                remediation_hint="Enable host firewall and review rules",
                os=os_family,
            )
        )

    if kernel.get("docker_socket_exists"):
        mode = kernel.get("docker_socket_mode")
        out.append(
            Finding(
                id="posture.docker_socket",
                title="Docker socket present",
                summary=f"Docker socket exists (mode={mode})",
                severity=Severity.LOW if mode else Severity.INFO,
                category="posture",
                evidence={
                    "docker_socket_exists": True,
                    "docker_socket_mode": mode,
                },
                confidence=0.6,
                remediation_hint="Ensure socket is not world-accessible",
                os=os_family,
            )
        )

    ww = fs.get("world_writable_hits") or []
    if ww:
        out.append(
            Finding(
                id="posture.world_writable_tmp",
                title="World-writable files in temp locations",
                summary=f"{len(ww)} world-writable file(s) sampled under temp",
                severity=Severity.LOW,
                category="posture",
                evidence={"paths": ww[:10]},
                confidence=0.55,
                remediation_hint="Review unexpected world-writable executables",
                os=os_family,
            )
        )

    return out
