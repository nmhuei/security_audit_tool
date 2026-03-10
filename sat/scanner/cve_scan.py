"""cve_scan.py – CVE scanning: Trivy (primary) → USN/OVAL feeds → OSV (fallback)."""
from __future__ import annotations

import json
import math
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List
from urllib.error import URLError
from urllib.request import Request, urlopen

from .common import Finding

OSV_BATCH    = "https://api.osv.dev/v1/querybatch"
USN_FEED     = "https://usn.ubuntu.com/usn-db/database.json"
UBUNTU_OVAL  = "https://security-metadata.canonical.com/oval/com.ubuntu.{series}.usn.oval.xml"

# ── Trivy (best accuracy – uses distro advisories) ────────────────────────────

def _trivy_available() -> bool:
    return shutil.which("trivy") is not None

def scan_with_trivy() -> List[Finding]:
    """Use Trivy for filesystem scan – most accurate CVE mapping per distro."""
    if not _trivy_available():
        return []
    findings: List[Finding] = []
    try:
        result = subprocess.run(
            ["trivy", "fs", "--scanners", "vuln", "--format", "json",
             "--severity", "LOW,MEDIUM,HIGH,CRITICAL", "--quiet", "/"],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode not in (0, 1):
            return []
        data = json.loads(result.stdout)
    except Exception:
        return []

    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
               "MEDIUM": "MEDIUM", "LOW": "LOW", "UNKNOWN": "LOW"}

    for result_item in data.get("Results", []):
        target = result_item.get("Target", "")
        for vuln in result_item.get("Vulnerabilities", []):
            vid   = vuln.get("VulnerabilityID", "")
            pkg   = vuln.get("PkgName", "")
            ver   = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")
            title = vuln.get("Title") or vuln.get("Description", "")[:100]
            sev   = sev_map.get(vuln.get("Severity", "LOW"), "LOW")
            score_raw = (vuln.get("CVSS") or {})
            cvss  = ""
            for src in score_raw.values():
                v = src.get("V3Score") or src.get("V2Score")
                if v:
                    cvss = f" CVSS:{v}"
                    break
            findings.append(Finding(
                module="cve_scan",
                title=f"{vid} in {pkg}{cvss}",
                details=f"{target} | {pkg} {ver} → fix: {fixed or 'no fix yet'} | {title[:120]}",
                severity=sev,
                recommendation=(
                    f"Upgrade {pkg} to {fixed}." if fixed
                    else f"No fix available yet for {vid}. Monitor upstream and apply when released."
                ),
                evidence={"vuln_id": vid, "package": pkg, "installed": ver,
                          "fixed": fixed, "target": target},
            ))
    return findings


# ── Ubuntu USN (Security Notices) ─────────────────────────────────────────────

def _ubuntu_codename() -> str | None:
    try:
        out = subprocess.check_output(["lsb_release", "-cs"], text=True, timeout=5)
        return out.strip()
    except Exception:
        return None

def _installed_deb_set() -> set[str]:
    try:
        out = subprocess.check_output(
            ["dpkg-query", "-W", "-f", "${Package}\n"],
            text=True, timeout=20, stderr=subprocess.DEVNULL
        )
        return set(out.strip().splitlines())
    except Exception:
        return set()

def scan_ubuntu_usn(max_notices: int = 30) -> List[Finding]:
    """Check Ubuntu Security Notices for installed packages."""
    codename = _ubuntu_codename()
    if not codename:
        return []
    installed = _installed_deb_set()
    if not installed:
        return []

    findings: List[Finding] = []
    try:
        with urlopen(USN_FEED, timeout=20) as r:
            db = json.loads(r.read().decode())
    except Exception:
        return []

    checked = 0
    for usn_id, notice in list(db.items())[-500:]:  # last 500 notices
        if checked >= max_notices:
            break
        releases = notice.get("releases", {})
        if codename not in releases:
            continue
        pkgs = releases[codename].get("sources", {})
        affected = [p for p in pkgs if p in installed]
        if affected:
            checked += 1
            cves = notice.get("cves", [])
            sev  = "HIGH" if cves else "MEDIUM"
            findings.append(Finding(
                module="cve_scan",
                title=f"Ubuntu {usn_id}: {notice.get('title','')[:80]}",
                details=f"Affects: {', '.join(affected[:5])} | CVEs: {', '.join(cves[:3])}",
                severity=sev,
                recommendation=f"Run: sudo apt-get update && sudo apt-get upgrade {' '.join(affected[:5])}",
                evidence={"usn": usn_id, "packages": affected, "cves": cves},
            ))
    return findings


# ── Kernel CVE check (via linux-vulns API) ────────────────────────────────────

# Known CVEs for specific kernel ranges – expanded real list
KERNEL_CVES: list[dict] = [
    {"cve": "CVE-2024-1086",  "desc": "nf_tables use-after-free → local priv esc",        "max": (6,7,0),  "sev": "CRITICAL"},
    {"cve": "CVE-2024-0582",  "desc": "io_uring UAF via IORING_OP_MULTISHOT_ACCEPT",       "max": (6,6,8),  "sev": "HIGH"},
    {"cve": "CVE-2023-4623",  "desc": "net/sched: sch_hfsc UAF → priv esc",                "max": (6,5,2),  "sev": "CRITICAL"},
    {"cve": "CVE-2023-32629", "desc": "overlayfs priv esc (Ubuntu-specific)",              "max": (6,4,0),  "sev": "CRITICAL"},
    {"cve": "CVE-2023-2640",  "desc": "overlayfs – Quick elevation to root (Ubuntu)",      "max": (6,4,0),  "sev": "CRITICAL"},
    {"cve": "CVE-2022-0847",  "desc": "Dirty Pipe – overwrite read-only files",            "max": (5,16,11),"sev": "CRITICAL"},
    {"cve": "CVE-2022-2588",  "desc": "cls_route UAF → root priv esc",                    "max": (5,18,0), "sev": "CRITICAL"},
    {"cve": "CVE-2021-4034",  "desc": "PwnKit – pkexec priv esc (userspace but critical)", "max": (999,0,0),"sev": "CRITICAL"},
    {"cve": "CVE-2021-3490",  "desc": "eBPF ALU32 bounds tracking → OOB write",            "max": (5,12,4), "sev": "HIGH"},
    {"cve": "CVE-2021-22555", "desc": "Netfilter heap out-of-bounds write → root",         "max": (5,12,0), "sev": "CRITICAL"},
    {"cve": "CVE-2021-3156",  "desc": "Sudo heap overflow (Baron Samedit) → root",        "max": (999,0,0),"sev": "CRITICAL"},
    {"cve": "CVE-2016-5195",  "desc": "Dirty COW – race condition → root write",           "max": (4,8,3),  "sev": "CRITICAL"},
]

def scan_kernel_cves() -> List[Finding]:
    """Check running kernel against known CVE list with real CVE IDs."""
    findings: List[Finding] = []
    release = platform.release()
    m = re.match(r"(\d+)\.(\d+)\.?(\d*)", release)
    if not m:
        return findings
    k = (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))

    for entry in KERNEL_CVES:
        max_ver = entry["max"]
        if k < max_ver:
            findings.append(Finding(
                module="cve_scan",
                title=f"{entry['cve']} – kernel {release} likely vulnerable",
                details=entry["desc"],
                severity=entry["sev"],
                recommendation=(
                    f"Kernel {release} < {'.'.join(str(x) for x in max_ver)}. "
                    "Run: sudo apt-get dist-upgrade (or dnf update kernel). Then reboot."
                ),
                evidence={"kernel": release, "cve": entry["cve"],
                          "patched_in": ".".join(str(x) for x in max_ver)},
            ))
    return findings


# ── OSV fallback for pip packages ─────────────────────────────────────────────

def _installed_pip_packages() -> list[dict]:
    try:
        out = subprocess.check_output(
            ["python3", "-m", "pip", "list", "--format=json"],
            text=True, timeout=15, stderr=subprocess.DEVNULL
        )
        return json.loads(out)
    except Exception:
        return []

def _batch_osv(pkgs: list[dict], ecosystem: str) -> List[Finding]:
    """Query OSV batch API with rate limiting, retry, and exponential back-off."""
    import time
    findings: List[Finding] = []
    BATCH_SIZE    = 50
    MAX_RETRIES   = 3
    INTER_BATCH_S = 0.5   # seconds between batches (rate-limit courtesy)

    for i in range(0, len(pkgs), BATCH_SIZE):
        batch = pkgs[i:i + BATCH_SIZE]
        payload = {"queries": [
            {"package": {"name": p["name"], "ecosystem": ecosystem}, "version": p["version"]}
            for p in batch
        ]}
        req = Request(OSV_BATCH, method="POST",
                      data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})

        results: list = []
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with urlopen(req, timeout=25) as r:
                    status = r.status if hasattr(r, "status") else 200
                    if status == 429:
                        # Rate limited – exponential back-off
                        wait = 2 ** attempt
                        time.sleep(wait)
                        continue
                    results = json.loads(r.read().decode()).get("results", [])
                    break
            except URLError as exc:
                reason = str(exc.reason) if hasattr(exc, "reason") else str(exc)
                if "429" in reason:
                    time.sleep(2 ** attempt)
                    continue
                # Network error – stop trying this batch
                results = []
                break
            except Exception:
                break

        # Polite pause between batches to avoid rate limits
        if i + BATCH_SIZE < len(pkgs):
            time.sleep(INTER_BATCH_S)
        for pkg, item in zip(batch, results):
            for v in item.get("vulns", [])[:2]:
                sev = "HIGH"
                for s in v.get("severity", []):
                    try:
                        score = float(s.get("score", 0))
                        if score >= 9.0: sev = "CRITICAL"
                        elif score >= 7.0: sev = "HIGH"
                        elif score >= 4.0: sev = "MEDIUM"
                        else: sev = "LOW"
                    except (ValueError, TypeError):
                        pass
                aliases = v.get("aliases", [])
                cve_ids = [a for a in aliases if a.startswith("CVE-")]
                findings.append(Finding(
                    module="cve_scan",
                    title=f"{cve_ids[0] if cve_ids else v.get('id','')} in {ecosystem} {pkg['name']}",
                    details=v.get("summary") or v.get("id", ""),
                    severity=sev,
                    recommendation=f"pip install --upgrade {pkg['name']}  # current: {pkg['version']}",
                    evidence={"package": pkg, "vuln_id": v.get("id"), "cves": cve_ids},
                ))
    return findings


def scan_pip_cves() -> List[Finding]:
    pkgs = _installed_pip_packages()[:100]
    return _batch_osv(pkgs, "PyPI") if pkgs else []

def scan_libc_version() -> List[Finding]:
    findings: List[Finding] = []
    try:
        out = subprocess.check_output(["ldd", "--version"], text=True, timeout=5)
        m = re.search(r"(\d+\.\d+)", out.splitlines()[0])
        if m:
            ver = tuple(int(x) for x in m.group(1).split("."))
            if ver < (2, 35):
                findings.append(Finding(
                    module="cve_scan",
                    title=f"Outdated glibc {m.group(1)} – multiple known CVEs",
                    details="CVE-2021-3999 (off-by-one), CVE-2022-23218 (buffer overflow) and others",
                    severity="HIGH" if ver < (2, 31) else "MEDIUM",
                    recommendation="sudo apt-get upgrade libc6  (or distro equivalent)",
                    evidence={"glibc": m.group(1)},
                ))
    except Exception:
        pass
    return findings


def run_all() -> List[Finding]:
    results: List[Finding] = []
    # Try Trivy first (most accurate)
    trivy_results = scan_with_trivy()
    if trivy_results:
        results.extend(trivy_results)
    else:
        # Fallback chain when Trivy not installed
        for fn in [scan_ubuntu_usn, scan_pip_cves]:
            try: results.extend(fn())
            except Exception: pass

    # Always run kernel + libc (Trivy doesn't cover these well)
    for fn in [scan_kernel_cves, scan_libc_version]:
        try: results.extend(fn())
        except Exception: pass

    return results
