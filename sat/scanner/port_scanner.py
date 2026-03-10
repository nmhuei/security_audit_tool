"""port_scanner.py – Local port scanner with banner grabbing and service fingerprinting."""
from __future__ import annotations

import concurrent.futures
import re
import socket
from typing import Iterable, List

from .common import Finding

COMMON_PORTS: list[int] = [
    20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 465, 514, 587, 636, 873, 993, 995, 1080,
    1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 4444, 5432, 5672,
    5900, 5984, 6379, 8080, 8443, 8888, 9000, 9200, 9300, 9418, 27017, 31337,
]

# Severity classification: port → (service_name, severity)
PORT_RISK: dict[int, tuple[str, str]] = {
    20:    ("FTP data",         "HIGH"),
    21:    ("FTP",              "HIGH"),
    23:    ("Telnet",           "CRITICAL"),
    69:    ("TFTP",             "HIGH"),
    111:   ("portmapper/RPC",   "HIGH"),
    119:   ("NNTP",             "MEDIUM"),
    135:   ("MS RPC",           "HIGH"),
    137:   ("NetBIOS-NS",       "HIGH"),
    138:   ("NetBIOS-DG",       "HIGH"),
    139:   ("NetBIOS-SSN",      "HIGH"),
    161:   ("SNMP",             "HIGH"),
    389:   ("LDAP",             "MEDIUM"),
    445:   ("SMB/CIFS",         "HIGH"),
    873:   ("rsync",            "MEDIUM"),
    1080:  ("SOCKS proxy",      "HIGH"),
    1433:  ("MSSQL",            "MEDIUM"),
    1521:  ("Oracle DB",        "MEDIUM"),
    2049:  ("NFS",              "HIGH"),
    2375:  ("Docker TCP",       "CRITICAL"),
    2376:  ("Docker TLS",       "HIGH"),
    3306:  ("MySQL",            "MEDIUM"),
    3389:  ("RDP",              "HIGH"),
    4444:  ("Suspicious",       "HIGH"),
    5432:  ("PostgreSQL",       "MEDIUM"),
    5672:  ("RabbitMQ",         "MEDIUM"),
    5900:  ("VNC",              "HIGH"),
    5984:  ("CouchDB",          "HIGH"),
    6379:  ("Redis",            "CRITICAL"),
    8080:  ("HTTP proxy/alt",   "MEDIUM"),
    9200:  ("Elasticsearch",    "CRITICAL"),
    9300:  ("Elasticsearch",    "HIGH"),
    9418:  ("Git daemon",       "MEDIUM"),
    27017: ("MongoDB",          "CRITICAL"),
    31337: ("Back Orifice?",    "CRITICAL"),
}

# Services that often expose banners on connect
BANNER_PORTS = {21, 22, 23, 25, 80, 110, 143, 443, 6379, 27017}

# Known safe banners that don't warrant extra warnings
_SAFE_BANNER_RE = re.compile(
    r"(SSH-\d|OpenSSH|220.*ESMTP|HTTP/1|IMAP|POP3)", re.IGNORECASE
)


def _check_port(host: str, port: int, timeout: float) -> int | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((host, port)) == 0:
            return port
    except OSError:
        return None
    finally:
        s.close()
    return None


def _grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    """Attempt to read a banner from an open port."""
    if port not in BANNER_PORTS:
        return ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # Send minimal HTTP request for port 80/8080/443
        if port in (80, 8080, 8443, 443):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        banner = s.recv(256).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:200]
    except Exception:
        return ""


def scan_open_ports(
    host: str = "127.0.0.1",
    ports: Iterable[int] | None = None,
    timeout: float = 0.5,
    grab_banners: bool = True,
) -> List[Finding]:
    ports_list = sorted(set(ports or COMMON_PORTS))
    open_ports: list[int] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as pool:
        futures = {pool.submit(_check_port, host, p, timeout): p for p in ports_list}
        for fut in concurrent.futures.as_completed(futures, timeout=max(10, len(ports_list) * timeout + 5)):
            try:
                result = fut.result()
                if result is not None:
                    open_ports.append(result)
            except Exception:
                pass

    findings: List[Finding] = []
    for p in sorted(open_ports):
        svc_name, sev = PORT_RISK.get(p, ("Unknown service", "LOW"))

        banner = ""
        banner_detail = ""
        if grab_banners:
            banner = _grab_banner(host, p, timeout=1.5)
            if banner and not _SAFE_BANNER_RE.search(banner):
                # Unexpected or unusual banner — worth noting
                banner_detail = f" | Banner: {banner[:80]}"

        findings.append(Finding(
            module="port_scanner",
            title=f"Open port: {p}/{svc_name}",
            details=f"Port {p} ({svc_name}) is open on {host}{banner_detail}",
            severity=sev,
            recommendation=(
                "Disable unused service, bind to 127.0.0.1 only, "
                "or restrict access via firewall."
            ),
            evidence={
                "host": host,
                "port": p,
                "service": svc_name,
                "banner": banner[:100] if banner else "",
            },
        ))

    return findings
