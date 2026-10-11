"""Shannon Entropy and Enterprise Secret Scanner for OWASP Sentinel."""

import math
import re
from typing import List, Tuple, Dict, Any
from .models import Finding, OWASPCategory, Severity

# Curated High-Fidelity Secret Signatures
ENTERPRISE_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "SEC-SEC-001",
        "title": "Google Cloud Service Account Private Key Disclosed",
        "pattern": r"\"type\"\s*:\s*\"service_account\".*\"private_key\"\s*:\s*\"-----BEGIN",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
        "description": "Embedded Google Cloud Service Account credentials grant programmatic access to cloud APIs and resources.",
        "remediation": "Remove the Service Account JSON key from source control and load credentials via GOOGLE_APPLICATION_CREDENTIALS environment variable or Workload Identity."
    },
    {
        "id": "SEC-SEC-002",
        "title": "Slack Webhook or Bot Token Disclosed",
        "pattern": r"(?:https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+|xox[baprs]-[0-9a-zA-Z\-]{10,48})",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
        "description": "Slack webhook URL or bot OAuth token exposed in source code, permitting unauthorized channel messaging and workspace access.",
        "remediation": "Revoke the Slack webhook/token and store it securely in a secret manager."
    },
    {
        "id": "SEC-SEC-003",
        "title": "GitHub Personal Access Token (Classic or Fine-Grained)",
        "pattern": r"(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|gho_[a-zA-Z0-9]{36})",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
        "description": "GitHub Personal Access Token exposed, granting repository and organization read/write permissions.",
        "remediation": "Revoke the token immediately on GitHub Settings -> Developer settings -> Personal access tokens."
    },
    {
        "id": "SEC-SEC-004",
        "title": "Database Connection String with Plaintext Password",
        "pattern": r"(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp)://[a-zA-Z0-9_.\-]+:[^@\s/]{3,}@[a-zA-Z0-9_.\-]+",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-312",
        "description": "Database connection URI contains embedded plaintext username and password.",
        "remediation": "Parameterize database credentials using environment variables: DATABASE_URL=postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
    },
    {
        "id": "SEC-SEC-005",
        "title": "SendGrid or Mailgun API Key Disclosed",
        "pattern": r"(?:SG\.[a-zA-Z0-9_\-\.]{22}\.[a-zA-Z0-9_\-\.]{43}|key-[0-9a-zA-Z]{32})",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
        "description": "Email delivery service API key exposed, which can be hijacked to send spam or phishing emails from your domain.",
        "remediation": "Revoke the API key and configure it securely via environment variables."
    }
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1

    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def scan_content_for_secrets(content: str, rel_path: str, lines: List[str]) -> List[Finding]:
    """Scan file content using enterprise signature matching and Shannon entropy analysis."""
    findings: List[Finding] = []

    # 1. High-Fidelity Enterprise Signatures
    for sig in ENTERPRISE_SECRET_PATTERNS:
        compiled = re.compile(sig["pattern"], re.MULTILINE)
        for match in compiled.finditer(content):
            char_offset = match.start()
            line_no = content[:char_offset].count("\n") + 1
            matched_line = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)

            # Redact actual secret text in snippet for security
            redacted_snippet = re.sub(r"(:[^\s@/]+@)", r":***@", matched_line)

            findings.append(Finding(
                rule_id=sig["id"],
                title=sig["title"],
                category=OWASPCategory.A02.value,
                severity=sig["severity"].value,
                cwe=sig["cwe"],
                file_path=rel_path,
                line_number=line_no,
                matched_line=redacted_snippet,
                code_snippet=redacted_snippet,
                description=sig["description"],
                remediation=sig["remediation"]
            ))

    # 2. Shannon Entropy Analysis for High-Entropy Random Tokens
    # Target string literals inside assignments like token = "..." or "secret": "..."
    token_pattern = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{24,120})['\"]")
    for idx, line in enumerate(lines, start=1):
        clean_l = line.strip()
        # Skip comments or imports
        if clean_l.startswith("#") or clean_l.startswith("//") or clean_l.startswith("import ") or "from " in clean_l:
            continue

        # Look for assignment contexts
        if any(keyword in clean_l.lower() for keyword in ["key", "secret", "token", "auth", "pass", "cred", "hash", "private"]):
            for match in token_pattern.finditer(clean_l):
                token_val = match.group(1)
                # Compute Shannon entropy
                entropy = calculate_shannon_entropy(token_val)
                # High entropy threshold (> 4.5 for mixed alphanumeric/base64 strings)
                if entropy >= 4.5 and len(token_val) >= 28:
                    # Filter out common false positives like URLs, hashes in comments, uuid
                    if token_val.startswith("http") or "-" in token_val and len(token_val) == 36:
                        continue

                    # Mask secret value
                    masked = token_val[:4] + "*" * (len(token_val) - 8) + token_val[-4:]
                    findings.append(Finding(
                        rule_id="SEC-A02-007",
                        title=f"High-Entropy Secret Detected (Entropy: {entropy:.2f})",
                        category=OWASPCategory.A02.value,
                        severity=Severity.HIGH.value,
                        cwe="CWE-798",
                        file_path=rel_path,
                        line_number=idx,
                        matched_line=clean_l.replace(token_val, masked),
                        code_snippet=f"{idx:4d} | >>> {clean_l.replace(token_val, masked)}",
                        description=f"High-entropy string literal detected (Shannon entropy {entropy:.2f}). This statistically indicates a cryptographically random secret key, authentication token, or private credential.",
                        remediation="Do not hardcode cryptographic secrets in source code. Load secrets from environment variables or a secure key management service (Vault, AWS Secrets Manager, etc.)."
                    ))

    return findings
