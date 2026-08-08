"""Network surface heuristic rules."""

from __future__ import annotations

from grok_inspect.models import Finding, ScanBundle, Severity


def apply(bundle: ScanBundle) -> list[Finding]:
    out: list[Finding] = []
    os_family = bundle.host.get("os_family")
    net = bundle.evidence_for("network")
    env = bundle.evidence_for("env")

    hosts = net.get("hosts_file_suspicious") or []
    if hosts:
        out.append(
            Finding(
                id="network.hosts_file_anomaly",
                title="Non-default hosts file entries",
                summary=f"{len(hosts)} suspicious hosts file line(s) (not localhost)",
                severity=Severity.MEDIUM,
                category="network",
                evidence={"lines": hosts[:15]},
                confidence=0.75,
                remediation_hint="Review /etc/hosts (or Windows hosts) for malicious redirects",
                os=os_family,
            )
        )

    proxy_env = env.get("proxy_env") or {}
    if proxy_env:
        out.append(
            Finding(
                id="network.proxy_env",
                title="HTTP(S) proxy environment variables set",
                summary=f"Proxy-related env vars present: {', '.join(sorted(proxy_env))}",
                severity=Severity.LOW,
                category="network",
                evidence={"proxy_env": proxy_env},
                confidence=0.7,
                remediation_hint="Confirm proxy is corporate/expected, not attacker MITM",
                os=os_family,
            )
        )

    wifi_proxy = net.get("proxy_wifi_web") or ""
    if isinstance(wifi_proxy, str) and "Enabled: Yes" in wifi_proxy:
        out.append(
            Finding(
                id="network.system_proxy_enabled",
                title="System web proxy enabled",
                summary="Wi-Fi web proxy appears enabled",
                severity=Severity.MEDIUM,
                category="network",
                evidence={"proxy": wifi_proxy[:300]},
                confidence=0.8,
                remediation_hint="Verify proxy host is trusted; unexpected proxies enable MITM",
                os=os_family,
            )
        )

    return out
