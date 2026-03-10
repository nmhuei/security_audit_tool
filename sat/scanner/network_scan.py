"""network_scan.py – Comprehensive local network security checks.

Checks:
  - Firewall status (ufw / firewalld / iptables)
  - Listening services via ss/netstat with risky-port classification
  - IP forwarding (potential pivot point)
  - Promiscuous mode interfaces (possible sniffer)
  - ARP cache anomalies (ARP spoofing detection)
  - DNS configuration checks
  - IPv6 without ip6tables rules
  - Routing table anomalies
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path
from typing import List

from .common import Finding


def _run(cmd: list[str], timeout: int = 8) -> str:
    try:
        return subprocess.check_output(
            cmd, text=True, timeout=timeout, stderr=subprocess.DEVNULL
        )
    except Exception:
        return ""


# ── 1. Firewall ───────────────────────────────────────────────────────────────

def scan_firewall_status() -> List[Finding]:
    findings: List[Finding] = []
    active = False

    ufw_out = _run(["ufw", "status"])
    if "active" in ufw_out.lower():
        active = True

    if not active:
        fw_out = _run(["firewall-cmd", "--state"])
        if "running" in fw_out.lower():
            active = True

    if not active:
        ipt = _run(["iptables", "-L", "-n", "--line-numbers"])
        non_default = [l for l in ipt.splitlines()
                       if l.strip() and not l.startswith("Chain") and not l.startswith("target")]
        if non_default:
            active = True

    if not active:
        findings.append(Finding(
            module="network_scan",
            title="No active firewall detected",
            details="ufw, firewalld, and iptables show no active rules.",
            severity="HIGH",
            recommendation=(
                "Enable a host firewall: `sudo ufw enable` (Ubuntu/Debian) "
                "or `sudo systemctl start firewalld` (RHEL/Fedora)."
            ),
            evidence={"checked": ["ufw", "firewalld", "iptables"]},
        ))
    return findings


# ── 2. Listening services ─────────────────────────────────────────────────────

RISKY_PORTS: dict[int, tuple[str, str]] = {
    21:    ("FTP",             "CRITICAL"),
    23:    ("Telnet",          "CRITICAL"),
    512:   ("rexec",           "CRITICAL"),
    513:   ("rlogin",          "CRITICAL"),
    514:   ("rsh",             "CRITICAL"),
    2375:  ("Docker TCP API",  "CRITICAL"),
    2376:  ("Docker TLS API",  "HIGH"),
    6379:  ("Redis",           "HIGH"),
    27017: ("MongoDB",         "HIGH"),
    9200:  ("Elasticsearch",   "HIGH"),
    9300:  ("Elasticsearch",   "HIGH"),
    5984:  ("CouchDB",         "HIGH"),
    5432:  ("PostgreSQL",      "MEDIUM"),
    3306:  ("MySQL/MariaDB",   "MEDIUM"),
    1433:  ("MSSQL",           "MEDIUM"),
    5900:  ("VNC",             "HIGH"),
    8080:  ("HTTP Alt",        "MEDIUM"),
    4444:  ("Suspicious port", "HIGH"),
    31337: ("Suspicious port", "HIGH"),
}


def scan_listening_services() -> List[Finding]:
    """Parse ss output to flag risky services listening on all interfaces."""
    findings: List[Finding] = []
    out = _run(["ss", "-tlnup"])

    addr_port_re = re.compile(r"(\d+\.\d+\.\d+\.\d+|\*|::|\[::\]):(\d+)")
    publicly_listening: dict[int, str] = {}

    for line in out.splitlines():
        if "LISTEN" not in line:
            continue
        m = addr_port_re.search(line)
        if not m:
            continue
        addr, port_str = m.group(1), m.group(2)
        port = int(port_str)
        if addr in ("0.0.0.0", "*", "::", "[::]"):
            publicly_listening[port] = addr

    for port, addr in sorted(publicly_listening.items()):
        if port in RISKY_PORTS:
            svc, sev = RISKY_PORTS[port]
            findings.append(Finding(
                module="network_scan",
                title=f"Risky service listening on all interfaces: {svc} port {port}",
                details=f"{svc} port {port} bound to {addr} – reachable from network.",
                severity=sev,
                recommendation=(
                    f"Bind {svc} to 127.0.0.1 only, firewall port {port}, "
                    "or disable the service if unused."
                ),
                evidence={"port": port, "address": addr, "service": svc},
            ))
    return findings


# ── 3. IP forwarding ──────────────────────────────────────────────────────────

def scan_ip_forwarding() -> List[Finding]:
    """Detect enabled IP forwarding (pivot risk on workstations)."""
    findings: List[Finding] = []
    checks = [
        (Path("/proc/sys/net/ipv4/ip_forward"), "IPv4", "net.ipv4.ip_forward"),
        (Path("/proc/sys/net/ipv6/conf/all/forwarding"), "IPv6",
         "net.ipv6.conf.all.forwarding"),
    ]
    for path, label, sysctl_key in checks:
        try:
            if path.read_text().strip() == "1":
                findings.append(Finding(
                    module="network_scan",
                    title=f"{label} IP forwarding is enabled",
                    details=f"{path} = 1 – host can route packets between interfaces.",
                    severity="MEDIUM",
                    recommendation=(
                        f"Disable unless this host is a router/VPN gateway: "
                        f"`sudo sysctl -w {sysctl_key}=0` and persist in /etc/sysctl.conf."
                    ),
                    evidence={"path": str(path), "sysctl": sysctl_key},
                ))
        except OSError:
            pass
    return findings


# ── 4. Promiscuous mode ───────────────────────────────────────────────────────

def scan_promiscuous_interfaces() -> List[Finding]:
    """Detect interfaces in promiscuous mode (possible packet sniffer)."""
    findings: List[Finding] = []
    out = _run(["ip", "link"])
    current_iface: str | None = None
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+(\S+):", line)
        if m:
            current_iface = m.group(1).rstrip("@:")
        if current_iface and "PROMISC" in line:
            findings.append(Finding(
                module="network_scan",
                title=f"Interface in promiscuous mode: {current_iface}",
                details=f"{current_iface} has PROMISC flag – capturing all traffic on segment.",
                severity="HIGH",
                recommendation=(
                    "Verify a legitimate capture tool set this. "
                    f"Disable: `sudo ip link set {current_iface} promisc off`"
                ),
                evidence={"interface": current_iface},
            ))
    return findings


# ── 5. ARP cache anomalies ────────────────────────────────────────────────────

def scan_arp_cache() -> List[Finding]:
    """Detect duplicate IP→MAC mappings (ARP spoofing / MITM indicator)."""
    findings: List[Finding] = []
    out = _run(["arp", "-n"]) or _run(["ip", "neigh"])
    if not out:
        return findings

    ip_to_macs: dict[str, set[str]] = {}
    mac_re = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
    ip_re  = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    for line in out.splitlines():
        ip_m  = ip_re.search(line)
        mac_m = mac_re.search(line)
        if ip_m and mac_m:
            ip  = ip_m.group(1)
            mac = mac_m.group(1).lower()
            ip_to_macs.setdefault(ip, set()).add(mac)

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            findings.append(Finding(
                module="network_scan",
                title=f"Possible ARP spoofing: {ip} → multiple MACs",
                details=f"IP {ip} resolves to MACs: {', '.join(sorted(macs))}",
                severity="HIGH",
                recommendation=(
                    "ARP spoofing (MITM) may be in progress. "
                    "Install `arpwatch` to monitor. Enable Dynamic ARP Inspection on switches."
                ),
                evidence={"ip": ip, "macs": list(macs)},
            ))
    return findings


# ── 6. DNS configuration ──────────────────────────────────────────────────────

PUBLIC_DNS: dict[str, str] = {
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
}


def scan_dns_config() -> List[Finding]:
    """Check /etc/resolv.conf for cleartext public DNS resolvers."""
    findings: List[Finding] = []
    resolv = Path("/etc/resolv.conf")
    if not resolv.exists():
        return findings
    try:
        text = resolv.read_text(errors="ignore")
    except OSError:
        return findings

    nameservers = re.findall(r"^nameserver\s+(\S+)", text, re.MULTILINE)
    if not nameservers:
        findings.append(Finding(
            module="network_scan",
            title="No DNS nameservers configured",
            details="Empty or missing nameserver lines in /etc/resolv.conf.",
            severity="MEDIUM",
            recommendation="Configure a reliable DNS nameserver.",
        ))

    for ns in nameservers:
        if ns in PUBLIC_DNS:
            findings.append(Finding(
                module="network_scan",
                title=f"Cleartext public DNS in use: {ns} ({PUBLIC_DNS[ns]})",
                details=f"DNS queries to {ns} are unencrypted (UDP/53) – potential DNS leak.",
                severity="LOW",
                recommendation=(
                    "Consider DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) "
                    "via systemd-resolved, Pi-hole, or AdGuard Home."
                ),
                evidence={"nameserver": ns, "provider": PUBLIC_DNS[ns]},
            ))
    return findings


# ── 7. IPv6 without ip6tables ─────────────────────────────────────────────────

def scan_ipv6_status() -> List[Finding]:
    """Warn if IPv6 global addresses exist but ip6tables has no rules."""
    findings: List[Finding] = []
    out = _run(["ip", "-6", "addr"])
    global_addrs = re.findall(r"inet6\s+([0-9a-fA-F:]+)/\d+\s+scope global", out)
    if not global_addrs:
        return findings

    ip6tables = _run(["ip6tables", "-L", "-n"])
    has_rules = any(
        line.strip() and not line.startswith("Chain") and not line.startswith("target")
        for line in ip6tables.splitlines()
    )
    if not has_rules:
        findings.append(Finding(
            module="network_scan",
            title="IPv6 active but no ip6tables rules detected",
            details=f"Global IPv6 addresses present: {', '.join(global_addrs[:3])}. No ip6tables rules found.",
            severity="MEDIUM",
            recommendation=(
                "Add IPv6 firewall rules: `sudo ip6tables -P INPUT DROP && "
                "sudo ip6tables -A INPUT -i lo -j ACCEPT`. "
                "Or disable IPv6: `net.ipv6.conf.all.disable_ipv6=1` in /etc/sysctl.conf."
            ),
            evidence={"ipv6_addresses": global_addrs[:5]},
        ))
    return findings


# ── 8. Routing table ──────────────────────────────────────────────────────────

def scan_interfaces_and_routes() -> List[Finding]:
    """Check routing table for anomalies."""
    findings: List[Finding] = []
    try:
        route = subprocess.check_output(["ip", "route"], text=True, timeout=5)
    except Exception:
        return findings

    if "default" not in route:
        findings.append(Finding(
            module="network_scan",
            title="No default route configured",
            details="No default route in routing table.",
            severity="MEDIUM",
            recommendation="Validate routing table and gateway settings.",
        ))

    for line in route.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            if "/" in parts[0]:
                net = ipaddress.ip_network(parts[0], strict=False)
                if net.prefixlen < 8:
                    findings.append(Finding(
                        module="network_scan",
                        title="Unusually broad route detected",
                        details=line.strip(),
                        severity="MEDIUM",
                        recommendation="Review broad routes – may bypass segmentation.",
                        evidence={"route": line.strip()},
                    ))
        except ValueError:
            continue
    return findings


# ── entry point ───────────────────────────────────────────────────────────────

def run_all() -> List[Finding]:
    results: List[Finding] = []
    for fn in [
        scan_firewall_status,
        scan_listening_services,
        scan_ip_forwarding,
        scan_promiscuous_interfaces,
        scan_arp_cache,
        scan_dns_config,
        scan_ipv6_status,
        scan_interfaces_and_routes,
    ]:
        try:
            results.extend(fn())
        except Exception:
            pass
    return results
