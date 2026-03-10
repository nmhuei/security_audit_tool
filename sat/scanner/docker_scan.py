"""docker_scan.py – Audit Docker daemon, socket exposure, and running containers."""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import List

from .common import Finding


def _docker_available() -> bool:
    try:
        subprocess.check_output(["docker", "info"], stderr=subprocess.DEVNULL, timeout=5)
        return True
    except Exception:
        return False


def scan_docker_socket() -> List[Finding]:
    """Check if Docker socket is world-accessible (critical privilege escalation vector)."""
    findings: List[Finding] = []
    sock = Path("/var/run/docker.sock")

    if not sock.exists():
        return findings

    try:
        mode = sock.stat().st_mode
        if mode & stat.S_IRWXO:
            findings.append(Finding(
                module="docker_scan",
                title="Docker socket is world-accessible",
                details=f"/var/run/docker.sock permissions: {oct(mode & 0o777)}",
                severity="CRITICAL",
                recommendation=(
                    "Set: `sudo chmod 660 /var/run/docker.sock && sudo chown root:docker /var/run/docker.sock`. "
                    "Ensure only trusted users are in the 'docker' group."
                ),
                evidence={"socket": str(sock), "mode": oct(mode & 0o777)},
            ))
        else:
            # Still report existence for awareness
            findings.append(Finding(
                module="docker_scan",
                title="Docker socket exists (verify group access)",
                details=f"/var/run/docker.sock mode: {oct(mode & 0o777)}",
                severity="LOW",
                recommendation="Only docker group members should access this socket.",
                evidence={"socket": str(sock), "mode": oct(mode & 0o777)},
            ))
    except OSError:
        pass
    return findings


def scan_privileged_containers() -> List[Finding]:
    """List running containers and flag privileged or host-network ones."""
    findings: List[Finding] = []
    if not _docker_available():
        return findings

    try:
        out = subprocess.check_output(
            ["docker", "inspect", "--format", "{{json .}}",
             "$(docker ps -q 2>/dev/null)"],
            shell=True, text=True, timeout=15, stderr=subprocess.DEVNULL
        )
    except Exception:
        try:
            # Fallback: list containers then inspect individually
            ids_out = subprocess.check_output(
                ["docker", "ps", "-q"], text=True, timeout=10, stderr=subprocess.DEVNULL
            ).split()
            if not ids_out:
                return findings
            out = subprocess.check_output(
                ["docker", "inspect"] + ids_out, text=True, timeout=15, stderr=subprocess.DEVNULL
            )
        except Exception:
            return findings

    try:
        containers = json.loads(out) if out.strip().startswith("[") else []
    except json.JSONDecodeError:
        return findings

    for c in containers:
        name = c.get("Name", "unknown").lstrip("/")
        host_config = c.get("HostConfig", {})
        net_mode = host_config.get("NetworkMode", "")

        if host_config.get("Privileged"):
            findings.append(Finding(
                module="docker_scan",
                title=f"Privileged container running: {name}",
                details="Container is running with --privileged flag (full host access)",
                severity="CRITICAL",
                recommendation="Remove --privileged and use specific capabilities (--cap-add) instead.",
                evidence={"container": name},
            ))

        if net_mode == "host":
            findings.append(Finding(
                module="docker_scan",
                title=f"Container using host network: {name}",
                details="Container shares host network namespace",
                severity="HIGH",
                recommendation="Use bridge networking unless host network is strictly required.",
                evidence={"container": name, "network": net_mode},
            ))

        # Check for dangerous capabilities
        cap_add = host_config.get("CapAdd") or []
        dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}
        bad_caps = [c for c in cap_add if c.upper() in dangerous_caps]
        if bad_caps:
            findings.append(Finding(
                module="docker_scan",
                title=f"Dangerous capabilities in container: {name}",
                details=f"CapAdd: {bad_caps}",
                severity="HIGH",
                recommendation="Remove unneeded capabilities. Never use CAP_SYS_ADMIN unless necessary.",
                evidence={"container": name, "capabilities": bad_caps},
            ))

        # Check mounted host paths
        mounts = c.get("Mounts", [])
        sensitive_paths = {"/", "/etc", "/root", "/proc", "/sys", "/var/run"}
        for mount in mounts:
            src = mount.get("Source", "")
            if any(src == sp or src.startswith(sp + "/") for sp in sensitive_paths):
                findings.append(Finding(
                    module="docker_scan",
                    title=f"Sensitive host path mounted in container: {name}",
                    details=f"Mount: {src} → {mount.get('Destination', '?')}",
                    severity="HIGH",
                    recommendation="Avoid mounting sensitive host paths. Use Docker volumes instead.",
                    evidence={"container": name, "source": src, "dest": mount.get("Destination")},
                ))
    return findings


def scan_docker_daemon_config() -> List[Finding]:
    """Check Docker daemon config for security settings."""
    findings: List[Finding] = []
    daemon_json = Path("/etc/docker/daemon.json")

    if not daemon_json.exists():
        findings.append(Finding(
            module="docker_scan",
            title="Docker daemon config not found",
            details="/etc/docker/daemon.json does not exist",
            severity="LOW",
            recommendation=(
                "Create /etc/docker/daemon.json with security defaults: "
                '{"icc": false, "no-new-privileges": true, "userns-remap": "default"}'
            ),
        ))
        return findings

    try:
        config = json.loads(daemon_json.read_text())
    except Exception:
        return findings

    if not config.get("userns-remap"):
        findings.append(Finding(
            module="docker_scan",
            title="Docker user namespace remapping not enabled",
            details="'userns-remap' not set in daemon.json",
            severity="MEDIUM",
            recommendation='Add "userns-remap": "default" to /etc/docker/daemon.json to isolate container UIDs.',
        ))

    if config.get("icc") is not False:
        findings.append(Finding(
            module="docker_scan",
            title="Inter-container communication (ICC) not disabled",
            details="'icc': false not set in daemon.json",
            severity="MEDIUM",
            recommendation='Add "icc": false to prevent containers communicating by default.',
        ))

    if not config.get("no-new-privileges"):
        findings.append(Finding(
            module="docker_scan",
            title="Docker no-new-privileges not enforced globally",
            details="'no-new-privileges': true not set in daemon.json",
            severity="LOW",
            recommendation='Add "no-new-privileges": true to prevent privilege escalation inside containers.',
        ))

    return findings


def run_all() -> List[Finding]:
    results: List[Finding] = []
    for fn in [scan_docker_socket, scan_privileged_containers, scan_docker_daemon_config]:
        try:
            results.extend(fn())
        except Exception:
            pass
    return results
