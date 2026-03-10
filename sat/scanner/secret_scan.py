"""secret_scan.py – High-accuracy secret detection with entropy scoring and allowlist."""
from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import List

from .common import Finding

# ── Entropy scoring ────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Shannon entropy – real secrets have high entropy (>3.5 bits/char)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def _is_high_entropy(value: str, threshold: float = 3.5) -> bool:
    return len(value) >= 16 and _shannon_entropy(value) >= threshold

# ── Allowlist – known safe values to ignore ────────────────────────────────────

ALLOWLIST_VALUES = {
    # Placeholder / example values
    "your_api_key_here", "changeme", "replace_me", "example", "placeholder",
    "your-token-here", "xxx", "yyy", "zzz", "test", "dummy", "fake",
    "abcdefghijklmnop", "1234567890123456", "aaaaaaaaaaaaaaaa",
    # AWS documented example keys
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # Common test/demo patterns
    "sk-xxxxxxxxxxxxxxxx", "insert_token_here", "token_goes_here",
    "<token>", "<api_key>", "${API_KEY}", "$(API_KEY)", "${SECRET}",
    "process.env.SECRET", "os.environ", "ENV_VAR", "env_var",
}

ALLOWLIST_PATTERNS = [
    re.compile(r"\$\{[A-Z_a-z]+\}"),      # ${ENV_VAR} anywhere in value
    re.compile(r"\$\([A-Z_a-z]+\)"),       # $(ENV_VAR) anywhere
    re.compile(r"^%[A-Z_]+%$"),            # %WINDOWS_ENV%
    re.compile(r"^<[a-z_]+>$"),            # <placeholder>
    re.compile(r"^[#*x]{8,}$"),            # ######## or xxxxxxxx
    re.compile(r"^example", re.I),
    re.compile(r"your[_-]?(api[_-]?)?key", re.I),
    re.compile(r"EXAMPLE$"),              # AKIAIOSFODNN7EXAMPLE etc.
    re.compile(r"^INSERT", re.I),
]

def _is_allowlisted(value: str) -> bool:
    v = value.lower().strip("'\"")
    if v in {x.lower() for x in ALLOWLIST_VALUES}:
        return True
    for pat in ALLOWLIST_PATTERNS:
        if pat.search(v):
            return True
    # All same character = not real
    if len(set(v)) < 4:
        return True
    return False

# ── Pattern definitions ────────────────────────────────────────────────────────
# Each entry: (label, compiled_regex, severity, needs_entropy_check, capture_group_for_value)

SECRET_PATTERNS: list[tuple[str, re.Pattern, str, bool, int]] = [
    # High-confidence patterns with fixed structure – no entropy needed
    ("AWS Access Key ID",
     re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
     "CRITICAL", False, 1),

    ("AWS Secret Access Key",
     re.compile(r"(?i)aws[_-]?secret[_-]?(access[_-]?)?key['\"]?\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
     "CRITICAL", False, 2),

    ("Private Key Block",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
     "CRITICAL", False, 0),

    ("GitHub Personal Access Token",
     re.compile(r"\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
     "CRITICAL", False, 1),

    ("Anthropic API Key",
     re.compile(r"\b(sk-ant-[A-Za-z0-9\-_]{40,})\b"),
     "CRITICAL", False, 1),

    ("OpenAI API Key",
     re.compile(r"\b(sk-[A-Za-z0-9]{48})\b"),
     "CRITICAL", False, 1),

    ("Slack Token",
     re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,48})\b"),
     "HIGH", False, 1),

    ("Stripe Secret Key",
     re.compile(r"\b(sk_live_[A-Za-z0-9]{24,})\b"),
     "CRITICAL", False, 1),

    ("GCP Service Account Key",
     re.compile(r'"type"\s*:\s*"service_account"'),
     "CRITICAL", False, 0),

    ("JWT Token",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
     "HIGH", False, 1),

    ("Database Connection URL",
     re.compile(r"(?i)\b((?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://[^@\s]{3,}@[^\s'\"]{5,})\b"),
     "HIGH", False, 1),

    ("Telegram Bot Token",
     re.compile(r"\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b"),
     "HIGH", True, 1),   # needs entropy – numeric prefix can match other things

    # Lower-confidence – require entropy validation
    ("Generic API Key/Token",
     re.compile(r"(?i)(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,64})['\"]?"),
     "HIGH", True, 1),

    ("Generic Secret/Password",
     re.compile(r"(?i)(?:^|\s)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s\$\{]{8,64})['\"]"),
     "MEDIUM", True, 1),

    ("Bearer Token in HTTP header",
     re.compile(r"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9_\-\.=]{20,})"),
     "HIGH", True, 1),
]

# ── File scanning config ───────────────────────────────────────────────────────

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
    "site-packages", ".cache", "vendor", "dist", "build", ".npm",
    ".gradle", "target", "coverage", "__tests__",
}
SCAN_EXTENSIONS = {
    ".env", ".conf", ".config", ".cfg", ".ini", ".yaml", ".yml",
    ".json", ".toml", ".sh", ".bash", ".zsh", ".py", ".rb", ".go",
    ".js", ".ts", ".php", ".java", ".xml", ".properties", ".tf",
    ".tfvars", ".pem", ".key", ".crt", ".log", ".txt",
}
MAX_FILE_SIZE = 512 * 1024
MAX_FINDINGS  = 100


def _should_scan(path: Path) -> bool:
    return (
        path.suffix.lower() in SCAN_EXTENSIONS
        or path.name.startswith(".env")
        or path.name in {"credentials", "config", "secrets", ".netrc", ".pgpass", "token", ".token"}
    )


def _scan_file(path: Path) -> list[Finding]:
    results: list[Finding] = []
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return results
        text = path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return results

    # Skip binary-looking files
    if "\x00" in text[:1024]:
        return results

    seen_labels: set[str] = set()

    for label, pattern, severity, needs_entropy, group in SECRET_PATTERNS:
        if label in seen_labels:
            continue
        m = pattern.search(text)
        if not m:
            continue

        try:
            value = m.group(group) if group > 0 else m.group(0)
        except IndexError:
            value = m.group(0)

        # Allowlist check
        if _is_allowlisted(value):
            continue

        # Entropy check for uncertain patterns
        if needs_entropy and not _is_high_entropy(value):
            continue

        # Extra: skip if value looks like a variable reference
        if any(c in value for c in ("$", "{", "}", "<", ">")):
            continue

        seen_labels.add(label)
        # Mask middle of value for display
        display = value[:6] + "..." + value[-4:] if len(value) > 12 else value[:4] + "..."
        line_no = text[:m.start()].count("\n") + 1

        results.append(Finding(
            module="secret_scan",
            title=f"Secret detected: {label}",
            details=f"{path}:{line_no} → {display}",
            severity=severity,
            recommendation=(
                "1. Rotate this credential immediately.\n"
                "   2. Move to env var / secrets manager (Vault, AWS SM, etc).\n"
                "   3. If committed to git: use BFG or `git filter-repo` to purge history."
            ),
            evidence={"file": str(path), "line": line_no, "pattern": label,
                      "masked_value": display, "entropy": round(_shannon_entropy(value), 2)},
        ))

        if len(results) >= 3:   # max 3 different secrets per file
            break

    return results


# ── Scanner functions ──────────────────────────────────────────────────────────

def scan_home_secrets(max_findings: int = MAX_FINDINGS) -> List[Finding]:
    findings: List[Finding] = []
    roots = list(Path("/home").iterdir()) + [Path("/root")]
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                p = Path(dirpath) / fname
                if _should_scan(p):
                    findings.extend(_scan_file(p))
                if len(findings) >= max_findings:
                    return findings
    return findings


def scan_env_variables() -> List[Finding]:
    """Check process env for secret-looking values (high-entropy only)."""
    findings: List[Finding] = []
    sensitive_key = re.compile(
        r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|APIKEY|API_KEY|AUTH)",
        re.IGNORECASE,
    )
    safe_keys = {"PATH", "TERM", "SHELL", "LANG", "LANGUAGE", "COLORTERM",
                 "TERM_PROGRAM", "LOGNAME", "USER", "HOME", "OLDPWD", "PWD"}

    for key, value in os.environ.items():
        if key in safe_keys:
            continue
        if not sensitive_key.search(key):
            continue
        if len(value) < 12:
            continue
        if _is_allowlisted(value):
            continue
        if not _is_high_entropy(value):
            continue
        findings.append(Finding(
            module="secret_scan",
            title=f"High-entropy secret in env var: {key}",
            details=f"Env var '{key}' = {value[:4]}...{value[-4:]} (entropy: {_shannon_entropy(value):.2f})",
            severity="MEDIUM",
            recommendation="Export secrets at runtime via a secrets manager, not shell profiles.",
            evidence={"key": key, "entropy": round(_shannon_entropy(value), 2), "length": len(value)},
        ))
    return findings


def scan_cloud_credential_files() -> List[Finding]:
    findings: List[Finding] = []
    cred_paths = [
        (".aws/credentials",                                   "AWS credentials",          "HIGH"),
        (".config/gcloud/application_default_credentials.json","GCP ADC",                  "HIGH"),
        (".config/gcloud/credentials.db",                      "GCP credentials DB",       "HIGH"),
        (".azure/accessTokens.json",                           "Azure tokens",             "HIGH"),
        (".kube/config",                                       "Kubernetes kubeconfig",    "HIGH"),
        (".netrc",                                             "netrc (embedded creds)",   "HIGH"),
        (".pgpass",                                            "PostgreSQL password file", "MEDIUM"),
        (".my.cnf",                                            "MySQL client config",      "MEDIUM"),
        (".docker/config.json",                                "Docker auth config",       "MEDIUM"),
        (".ssh/id_rsa",                                        "RSA private key",          "CRITICAL"),
        (".ssh/id_ed25519",                                    "Ed25519 private key",      "CRITICAL"),
        (".ssh/id_ecdsa",                                      "ECDSA private key",        "CRITICAL"),
    ]
    for home in list(Path("/home").iterdir()) + [Path("/root")]:
        for rel, label, sev in cred_paths:
            p = home / rel
            if not p.exists():
                continue
            try:
                mode = oct(p.stat().st_mode & 0o777)
                size = p.stat().st_size
                # Extra check: private keys should be mode 600
                if "private key" in label.lower() and p.stat().st_mode & 0o077:
                    sev = "CRITICAL"
                findings.append(Finding(
                    module="secret_scan",
                    title=f"Credential file found: {label}",
                    details=f"{p} (mode={mode}, size={size}B)",
                    severity=sev,
                    recommendation=f"chmod 600 {p} — verify it's not tracked in git — rotate regularly.",
                    evidence={"path": str(p), "mode": mode, "size": size},
                ))
            except OSError:
                pass
    return findings


def scan_git_config_secrets() -> List[Finding]:
    """Check .git/config files for embedded credentials in remote URLs."""
    findings: List[Finding] = []
    url_with_creds = re.compile(r"https?://[^@\s:]+:[^@\s]+@")
    for home in list(Path("/home").iterdir()) + [Path("/root")]:
        for git_cfg in home.rglob(".git/config"):
            try:
                text = git_cfg.read_text(errors="ignore")
                if url_with_creds.search(text):
                    findings.append(Finding(
                        module="secret_scan",
                        title="Credentials embedded in git remote URL",
                        details=str(git_cfg),
                        severity="HIGH",
                        recommendation=(
                            "Remove credentials from URL. Use SSH keys or git credential helper instead. "
                            "Run: git remote set-url origin git@github.com:user/repo.git"
                        ),
                        evidence={"file": str(git_cfg)},
                    ))
            except (PermissionError, OSError):
                pass
    return findings


def run_all() -> List[Finding]:
    results: List[Finding] = []
    for fn in [scan_home_secrets, scan_env_variables,
               scan_cloud_credential_files, scan_git_config_secrets]:
        try:
            results.extend(fn())
        except Exception:
            pass
    return results
