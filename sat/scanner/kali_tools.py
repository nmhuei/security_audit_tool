"""
kali_tools.py – Parallel wrappers for Kali/Debian security tools.
Each tool runs in its own thread with individual timeout.
Fast mode: lynis, nmap (no vuln scripts), fail2ban, auditd, debsums
Deep mode: adds --script vuln,auth to nmap, runs rkhunter, tiger, aide
"""
from __future__ import annotations

import json, re, shutil, subprocess, tempfile, xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutTimeoutError
from pathlib import Path
from typing import List

from .common import Finding

# ── individual tool timeouts (seconds) ───────────────────────────────────────
TOOL_TIMEOUTS = {
    "lynis":      240,
    "chkrootkit": 180,
    "rkhunter":   300,
    "nmap_fast":   60,
    "nmap_deep":  300,
    "nikto":      150,
    "debsums":    300,
    "tiger":      180,
    "aide":       300,
    "fail2ban":    15,
    "auditd":      10,
}

def _available(t: str) -> bool:
    return shutil.which(t) is not None

def _run(cmd, timeout=120) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", "not found"
    except Exception as e:
        return -1, "", str(e)

def _f(tool, title, details, severity="MEDIUM", rec="", evidence=None) -> Finding:
    return Finding(module=f"kali:{tool}", title=title, details=details,
                   severity=severity, recommendation=rec,
                   evidence=evidence or {"tool": tool})

def _not_installed(tool) -> List[Finding]:
    return [_f(tool, f"{tool} not installed",
               f"Install: sudo apt-get install {tool}", "LOW",
               f"sudo apt-get install {tool}")]

# ── 1. Lynis ──────────────────────────────────────────────────────────────────

def run_lynis() -> List[Finding]:
    if not _available("lynis"):
        return _not_installed("lynis")
    findings = []
    rc, out, _ = _run(
        ["lynis", "audit", "system", "--quick", "--quiet", "--no-colors"],
        timeout=TOOL_TIMEOUTS["lynis"],
    )
    hi = re.search(r"Hardening index\s*:\s*(\d+)", out)
    if hi:
        score = int(hi.group(1))
        sev = "CRITICAL" if score < 40 else "HIGH" if score < 60 else "MEDIUM" if score < 75 else "LOW"
        findings.append(_f("lynis", f"Lynis hardening score: {score}/100",
            f"Score {score}/100 – {'poor' if score<50 else 'fair' if score<70 else 'good'}",
            sev, "sudo lynis audit system  →  address warnings first",
            {"score": score}))

    # Parse warnings
    for m in re.finditer(r"^\s*!\s+(.+)", out, re.MULTILINE):
        txt = m.group(1).strip()
        if txt and len(findings) < 50:
            findings.append(_f("lynis", f"Lynis WARNING: {txt[:80]}", txt, "HIGH",
                "Run: sudo lynis audit system  →  Warnings section"))

    # Auto-fix hints from lynis TEST IDs
    report_file = Path("/var/log/lynis-report.dat")
    if report_file.exists():
        try:
            rpt = report_file.read_text(errors="ignore")
            for warn in re.findall(r"warning\[\]=(.+)", rpt)[:20]:
                findings.append(_f("lynis", f"Lynis: {warn[:80]}", warn, "HIGH",
                    f"Fix: {_lynis_fix_hint(warn)}"))
        except Exception:
            pass

    if not findings:
        findings.append(_f("lynis", "Lynis: no warnings found",
            "System passed lynis quick audit", "LOW"))
    return findings

def _lynis_fix_hint(warning: str) -> str:
    """Map common lynis warning strings to fix commands."""
    w = warning.lower()
    if "ssh" in w and "root" in w:
        return "sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd"
    if "password" in w and "ssh" in w:
        return "sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd"
    if "firewall" in w or "ufw" in w:
        return "ufw default deny incoming && ufw allow ssh && ufw --force enable"
    if "aide" in w:
        return "apt-get install aide && aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    if "fail2ban" in w:
        return "apt-get install fail2ban && systemctl enable --now fail2ban"
    if "auditd" in w:
        return "apt-get install auditd && systemctl enable --now auditd"
    if "umask" in w:
        return "echo 'umask 027' >> /etc/profile"
    if "core dump" in w:
        return "echo '* hard core 0' >> /etc/security/limits.conf"
    if "sysctl" in w or "kernel" in w:
        return "sysctl -w kernel.dmesg_restrict=1 kernel.kptr_restrict=2"
    return "Review lynis output: sudo lynis show details " + warning.split()[0] if warning.split() else "sudo lynis audit system"

# ── 2. chkrootkit ─────────────────────────────────────────────────────────────

CHKROOTKIT_RESPONSE_PLAYBOOK = """
🚨 INCIDENT RESPONSE PLAYBOOK – Possible Rootkit Detected:
1. DO NOT REBOOT (may destroy evidence)
2. Isolate: disconnect network  →  ip link set eth0 down
3. Preserve evidence: dd if=/dev/sda of=/mnt/external/disk.img bs=4M
4. Boot from trusted live USB (Kali/Ubuntu) for offline analysis
5. Cross-check with rkhunter: sudo rkhunter --check
6. Scan with chkrootkit offline: chkrootkit -r /mnt/suspect_root
7. If confirmed: reinstall OS from trusted media, rotate ALL credentials
8. Report & document before remediation
"""

def run_chkrootkit() -> List[Finding]:
    if not _available("chkrootkit"):
        return _not_installed("chkrootkit")
    findings = []
    rc, out, _ = _run(["chkrootkit", "-q"], timeout=TOOL_TIMEOUTS["chkrootkit"])
    infected_re = re.compile(r"INFECTED|Possible rootkit|Suspect file|trojan", re.I)
    for line in out.splitlines():
        s = line.strip()
        if not s or "nothing found" in s.lower():
            continue
        if infected_re.search(s):
            findings.append(_f("chkrootkit", f"🚨 Rootkit indicator: {s[:80]}", s,
                "CRITICAL", CHKROOTKIT_RESPONSE_PLAYBOOK,
                {"tool": "chkrootkit", "line": s}))
        elif "warning" in s.lower():
            findings.append(_f("chkrootkit", f"chkrootkit warning: {s[:80]}", s, "MEDIUM",
                "Investigate: sudo chkrootkit -v"))
    if not findings:
        findings.append(_f("chkrootkit", "chkrootkit: no rootkits detected",
            "All checks passed", "LOW"))
    return findings

# ── 3. rkhunter ───────────────────────────────────────────────────────────────

def run_rkhunter() -> List[Finding]:
    if not _available("rkhunter"):
        return _not_installed("rkhunter")
    _run(["rkhunter", "--update", "--nocolors"], timeout=60)
    rc, out, err = _run(
        ["rkhunter", "--check", "--skip-keypress", "--nocolors",
         "--report-warnings-only", "--quiet"],
        timeout=TOOL_TIMEOUTS["rkhunter"],
    )
    findings = []
    for line in (out + err).splitlines():
        s = line.strip()
        m = re.search(r"Warning:\s*(.+)", s)
        if m:
            msg = m.group(1).strip()
            sev = "CRITICAL" if any(k in msg.lower() for k in
                                    ["rootkit","backdoor","trojan","exploit"]) else "HIGH"
            findings.append(_f("rkhunter", f"rkhunter: {msg[:80]}", msg, sev,
                "Run: sudo rkhunter --check  →  investigate each warning",
                {"tool": "rkhunter", "warning": msg}))
        elif "INFECTED" in s:
            findings.append(_f("rkhunter", f"rkhunter INFECTED: {s[:80]}", s,
                "CRITICAL", CHKROOTKIT_RESPONSE_PLAYBOOK))
    if not findings:
        findings.append(_f("rkhunter", "rkhunter: no threats detected",
            "All rkhunter checks passed", "LOW"))
    return findings

# ── 4. nmap ───────────────────────────────────────────────────────────────────

DANGEROUS_PORTS = {21,23,25,110,111,135,139,445,512,513,514,
                   1099,2049,2375,3306,5432,5900,6379,27017}

def run_nmap(deep: bool = False) -> List[Finding]:
    if not _available("nmap"):
        return _not_installed("nmap")
    findings = []

    if deep:
        # Full version + vuln scripts (slow, thorough)
        cmd = ["nmap", "-sV", "-sC", "--open", "-T4",
               "--script", "vuln,auth,default", "-oX", "-", "127.0.0.1"]
        timeout = TOOL_TIMEOUTS["nmap_deep"]
    else:
        # Fast: version detect only, no slow scripts
        cmd = ["nmap", "-sV", "--open", "-T4", "-oX", "-", "127.0.0.1"]
        timeout = TOOL_TIMEOUTS["nmap_fast"]

    rc, out, _ = _run(cmd, timeout=timeout)
    if rc < 0:
        return []

    try:
        root = ET.fromstring(out)
    except ET.ParseError:
        return _parse_nmap_text(out)

    for port_el in root.findall(".//port"):
        portid = int(port_el.get("portid", 0))
        state  = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc    = port_el.find("service")
        name   = svc.get("name", "unknown") if svc is not None else "unknown"
        prod   = (svc.get("product", "") or "") if svc is not None else ""
        ver    = (svc.get("version", "") or "") if svc is not None else ""
        full   = f"{prod} {ver}".strip()
        sev    = "HIGH" if portid in DANGEROUS_PORTS else "MEDIUM"

        findings.append(_f("nmap", f"Open port {portid} — {name} {full}".strip(),
            f"127.0.0.1:{portid} → {name} {full}".strip(), sev,
            f"Disable {name} if unused or restrict with firewall.",
            {"port": portid, "service": name, "version": full}))

        # Vuln/auth script results (only in deep mode)
        for script in port_el.findall("script"):
            sid, sout = script.get("id", ""), script.get("output", "")
            if not sout:
                continue
            if "vuln" in sid and "VULNERABLE" in sout.upper():
                findings.append(_f("nmap",
                    f"nmap vuln script: {sid} port {portid}",
                    sout[:300], "CRITICAL",
                    f"Patch service on port {portid}.",
                    {"port": portid, "script": sid}))
            if "auth" in sid and any(k in sout.lower() for k in
                                     ["valid credentials","login success","anonymous"]):
                findings.append(_f("nmap",
                    f"Default credentials on {name} port {portid}",
                    sout[:200], "CRITICAL",
                    f"Change default credentials on {name} (port {portid}).",
                    {"port": portid, "script": sid}))

    # OS detection
    for osm in root.findall(".//osmatch")[:1]:
        findings.append(_f("nmap",
            f"OS fingerprint: {osm.get('name','')} ({osm.get('accuracy','')}%)",
            osm.get("name",""), "LOW", "Ensure OS is patched.",
            {"os": osm.get("name","")}))

    return findings

def _parse_nmap_text(out: str) -> List[Finding]:
    findings = []
    for line in out.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            port, proto, svc, ver = m.groups()
            findings.append(_f("nmap", f"Open {proto}/{port} — {svc} {ver}".strip(),
                f"{svc} {ver}".strip(),
                "HIGH" if int(port) in DANGEROUS_PORTS else "MEDIUM",
                f"Verify {svc} on port {port} is needed.",
                {"port": int(port), "service": svc}))
    return findings

# ── 5. Nikto ──────────────────────────────────────────────────────────────────

def run_nikto() -> List[Finding]:
    if not _available("nikto"):
        return _not_installed("nikto")
    import socket
    web_ports = []
    for p in [80, 443, 8080, 8443, 3000, 8000, 8888]:
        s = socket.socket()
        s.settimeout(0.3)
        if s.connect_ex(("127.0.0.1", p)) == 0:
            web_ports.append(p)
        s.close()
    if not web_ports:
        return []

    findings = []
    for port in web_ports[:3]:
        cmd = ["nikto", "-h", "127.0.0.1", "-p", str(port),
               "-Format", "txt", "-nointeractive", "-maxtime", "90s"]
        if port in (443, 8443):
            cmd.append("-ssl")
        rc, out, _ = _run(cmd, timeout=TOOL_TIMEOUTS["nikto"])
        for line in out.splitlines():
            s = line.strip()
            if not s.startswith("+"):
                continue
            if any(k in s for k in ["Target","Start Time","End Time","Server:","0 host"]):
                continue
            lower = s.lower()
            sev = ("HIGH" if any(k in lower for k in ["osvdb","cve-","xss","sql","rfi","lfi","shell"]) else
                   "MEDIUM" if any(k in lower for k in ["vulnerable","outdated","insecure","default"]) else "LOW")
            findings.append(_f("nikto", f"Nikto [{port}]: {s[2:60]}", s[2:300], sev,
                f"Investigate web finding on port {port}.",
                {"port": port, "finding": s[2:300]}))
    return findings

# ── 6. debsums ────────────────────────────────────────────────────────────────

def run_debsums() -> List[Finding]:
    if not _available("debsums"):
        return _not_installed("debsums")
    findings = []
    rc, out, err = _run(["debsums", "-s", "-a"], timeout=TOOL_TIMEOUTS["debsums"])
    pkg_failures: dict[str, list[str]] = {}
    for line in (out + err).splitlines():
        m = re.match(r"(/\S+)\s+FAILED", line.strip())
        if m:
            filepath = m.group(1)
            rc2, pout, _ = _run(["dpkg", "-S", filepath], timeout=5)
            pkg = pout.split(":")[0].strip() if rc2 == 0 and ":" in pout else "unknown"
            pkg_failures.setdefault(pkg, []).append(filepath)
    for pkg, files in list(pkg_failures.items())[:30]:
        is_crit = any(f.startswith(("/bin/","/sbin/","/usr/bin/","/usr/sbin/",
                                    "/lib/","/usr/lib/","/etc/")) for f in files)
        findings.append(_f("debsums",
            f"Package integrity failure: {pkg} ({len(files)} file(s))",
            f"Modified: {', '.join(files[:5])}",
            "CRITICAL" if is_crit else "HIGH",
            f"sudo apt-get install --reinstall {pkg}  (if system binaries: suspect compromise)",
            {"package": pkg, "failed_files": files[:10]}))
    if not pkg_failures:
        findings.append(_f("debsums", "debsums: all package files intact",
            "No integrity failures", "LOW"))
    return findings

# ── 7. Tiger ──────────────────────────────────────────────────────────────────

def run_tiger() -> List[Finding]:
    if not _available("tiger"):
        return _not_installed("tiger")
    findings = []
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, err = _run(["tiger", "-q", "-B", tmp], timeout=TOOL_TIMEOUTS["tiger"])
        for line in (out + err).splitlines():
            s = line.strip()
            if s.startswith("FAIL"):
                findings.append(_f("tiger", f"Tiger FAIL: {s[5:80]}", s[5:], "HIGH",
                    "sudo tiger -q  →  review FAIL items"))
            elif s.startswith("WARN"):
                findings.append(_f("tiger", f"Tiger WARN: {s[5:80]}", s[5:], "MEDIUM",
                    "sudo tiger -q  →  review WARN items"))
    return findings[:20]

# ── 8. AIDE ───────────────────────────────────────────────────────────────────

def run_aide() -> List[Finding]:
    if not _available("aide"):
        return [_f("aide", "aide not installed",
            "Install + init: sudo apt-get install aide && sudo aideinit", "LOW",
            "sudo apt-get install aide && sudo aideinit")]
    db = Path("/var/lib/aide/aide.db")
    if not db.exists():
        return [_f("aide", "AIDE database not initialised",
            "Run sudo aideinit first", "MEDIUM",
            "sudo aideinit && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db")]
    findings = []
    rc, out, err = _run(["aide", "--check"], timeout=TOOL_TIMEOUTS["aide"])
    if rc == 0:
        findings.append(_f("aide", "AIDE: no integrity violations", "All files intact", "LOW"))
        return findings
    change_re = re.compile(r"^(changed|removed|added):\s+(.+)", re.I)
    by_action: dict[str, list[str]] = {}
    for line in (out + err).splitlines():
        m = change_re.match(line.strip())
        if m:
            by_action.setdefault(m.group(1).lower(), []).append(m.group(2).strip())
    for action, files in by_action.items():
        is_crit = any(f.startswith(("/bin/","/sbin/","/usr/bin/","/etc/",
                                    "/lib/","/usr/lib/")) for f in files)
        findings.append(_f("aide", f"AIDE: {len(files)} file(s) {action}",
            f"Files {action}: {', '.join(files[:5])}{'...' if len(files)>5 else ''}",
            "CRITICAL" if (is_crit and action == "changed") else "HIGH",
            "If unexpected: investigate compromise. Update DB: sudo aide --update",
            {"action": action, "files": files[:20]}))
    return findings

# ── 9. fail2ban ───────────────────────────────────────────────────────────────

def run_fail2ban_check() -> List[Finding]:
    if not _available("fail2ban-client"):
        return [_f("fail2ban", "fail2ban not installed",
            "Protects against brute-force attacks", "MEDIUM",
            "sudo apt-get install fail2ban && sudo systemctl enable --now fail2ban")]
    rc, out, _ = _run(["fail2ban-client", "status"], timeout=TOOL_TIMEOUTS["fail2ban"])
    if rc != 0 or "not running" in out.lower():
        return [_f("fail2ban", "fail2ban is not running", "", "HIGH",
            "sudo systemctl enable --now fail2ban")]
    jails_m = re.search(r"Jail list:\s*(.+)", out)
    jails = [j.strip() for j in jails_m.group(1).split(",")] if jails_m else []
    total_banned = 0
    for jail in jails:
        rc2, jout, _ = _run(["fail2ban-client", "status", jail], timeout=10)
        m = re.search(r"Currently banned:\s*(\d+)", jout)
        if m:
            total_banned += int(m.group(1))
    return [_f("fail2ban",
        f"fail2ban active — {len(jails)} jail(s), {total_banned} banned",
        f"Jails: {', '.join(jails[:10])}", "LOW",
        "fail2ban protecting system.",
        {"jails": jails, "total_banned": total_banned})]

# ── 10. auditd ────────────────────────────────────────────────────────────────

def run_auditd_check() -> List[Finding]:
    if not _available("auditctl"):
        return [_f("auditd", "auditd not installed",
            "Kernel-level syscall auditing", "MEDIUM",
            "sudo apt-get install auditd && sudo systemctl enable --now auditd")]
    rc, out, _ = _run(["auditctl", "-s"], timeout=TOOL_TIMEOUTS["auditd"])
    if "enabled 0" in out or rc != 0:
        return [_f("auditd", "auditd is disabled", "", "HIGH",
            "sudo systemctl enable --now auditd && sudo auditctl -e 1")]
    rc2, rules, _ = _run(["auditctl", "-l"], timeout=10)
    n = len([l for l in rules.splitlines() if l.strip() and not l.startswith("#")])
    sev = "MEDIUM" if n < 5 else "LOW"
    msg = (f"only {n} rule(s)" if n < 5 else f"{n} rule(s) configured")
    return [_f("auditd", f"auditd running — {msg}", msg, sev,
        "https://github.com/Neo23x0/auditd for CIS ruleset",
        {"rule_count": n})]


# ── Registry + parallel runner ────────────────────────────────────────────────

TOOL_RUNNERS_FAST = {
    "lynis":     run_lynis,
    "nmap":      lambda: run_nmap(deep=False),
    "debsums":   run_debsums,
    "fail2ban":  run_fail2ban_check,
    "auditd":    run_auditd_check,
    "chkrootkit":run_chkrootkit,
}
TOOL_RUNNERS_DEEP = {
    **TOOL_RUNNERS_FAST,
    "nmap":      lambda: run_nmap(deep=True),   # override with deep
    "rkhunter":  run_rkhunter,
    "nikto":     run_nikto,
    "tiger":     run_tiger,
    "aide":      run_aide,
}

TOOL_RUNNERS = {   # full set for list_tools()
    **TOOL_RUNNERS_DEEP,
}

TOOL_DESCRIPTIONS = {
    "lynis":      "Comprehensive system hardening audit (score 0-100)",
    "chkrootkit": "Rootkit & backdoor detection",
    "rkhunter":   "Rootkit Hunter – second opinion",
    "nmap":       "Service/version fingerprinting (+ vuln scripts in deep mode)",
    "nikto":      "Web server vulnerability scan",
    "debsums":    "Package file integrity via checksums (Debian/Ubuntu)",
    "tiger":      "Classic UNIX security audit",
    "aide":       "File integrity monitoring",
    "fail2ban":   "Brute-force protection status",
    "auditd":     "Linux kernel audit daemon",
}

def list_tools() -> dict[str, dict]:
    binary_map = {"fail2ban": "fail2ban-client", "auditd": "auditctl"}
    return {
        name: {
            "description": TOOL_DESCRIPTIONS.get(name, ""),
            "installed":   _available(binary_map.get(name, name)),
            "binary":      binary_map.get(name, name),
        }
        for name in TOOL_RUNNERS
    }

def run_all(tools: list[str] | None = None, deep: bool = False) -> List[Finding]:
    """Run tools in parallel, each with its own timeout."""
    runners = TOOL_RUNNERS_DEEP if deep else TOOL_RUNNERS_FAST
    selected = {k: v for k, v in runners.items()
                if tools is None or k in tools}

    findings: List[Finding] = []
    # Per-tool timeout = tool-specific + 10s buffer
    with ThreadPoolExecutor(max_workers=min(6, len(selected))) as pool:
        future_to_name = {pool.submit(fn): name for name, fn in selected.items()}
        for fut in as_completed(future_to_name, timeout=350):
            name = future_to_name[fut]
            try:
                findings.extend(fut.result())
            except FutTimeoutError:
                findings.append(_f(name, f"{name} timed out",
                    "Tool exceeded timeout", "LOW",
                    f"Run manually: sudo {name}"))
            except Exception as e:
                findings.append(_f(name, f"{name} error", str(e), "LOW"))
    return findings
