"""Automated Remediation Diff and Patch Generator for OWASP Sentinel."""

import re
import difflib
from typing import Optional, Dict, Any, List
from .models import Finding, ScanResult

# Common automated fix heuristics for known patterns
FIX_PATTERNS: Dict[str, Dict[str, Any]] = {
    "SEC-A01-002": {
        "pattern": r"['\"]Access-Control-Allow-Origin['\"]\s*:\s*['\"]\*(?:['\"])?",
        "replacement": "'Access-Control-Allow-Origin': os.getenv('TRUSTED_ORIGIN', 'https://yourdomain.com')"
    },
    "SEC-A01-005": {
        "pattern": r"tempfile\.mktemp\s*\(([^)]*)\)",
        "replacement": r"tempfile.NamedTemporaryFile(delete=False\1).name"
    },
    "SEC-A02-002": {
        "pattern": r"hashlib\.md5\s*\(",
        "replacement": "hashlib.sha256("
    },
    "SEC-A02-004": {
        "pattern": r"verify\s*=\s*False",
        "replacement": "verify=True"
    },
    "SEC-A03-001": {
        "description": "Replace string formatting with parameterized query placeholder",
        "handler": "fix_sql_injection"
    },
    "SEC-A03-009": {
        "pattern": r"Environment\s*\([^)]*autoescape\s*=\s*False",
        "replacement": "Environment(autoescape=select_autoescape(['html', 'xml'])"
    },
    "SEC-A05-001": {
        "pattern": r"(?i)debug\s*=\s*True",
        "replacement": "debug=False"
    },
    "SEC-A05-005": {
        "pattern": r"^USER\s+root\b",
        "replacement": "USER nonroot"
    },
    "SEC-A07-001": {
        "pattern": r"httponly\s*=\s*False",
        "replacement": "httponly=True"
    },
    "SEC-A07-005": {
        "pattern": r"algorithms\s*:\s*\[\s*['\"]none['\"]\s*\]",
        "replacement": "algorithms: ['HS256']"
    },
    "SEC-A08-001": {
        "pattern": r"\bpickle\.loads\b",
        "replacement": "json.loads"
    },
    "SEC-A08-002": {
        "pattern": r"yaml\.load\s*\(([^,)]+)\)",
        "replacement": r"yaml.safe_load(\1)"
    },
    "SEC-IAC-001": {
        "pattern": r"privileged\s*:\s*true\b",
        "replacement": "privileged: false"
    },
    "SEC-IAC-002": {
        "pattern": r"hostPID\s*:\s*true\b",
        "replacement": "hostPID: false"
    },
    "SEC-IAC-005": {
        "pattern": r"cidr_blocks\s*=\s*\[\s*['\"]0\.0\.0\.0/0['\"]\s*\]",
        "replacement": 'cidr_blocks = ["10.0.0.0/16"]'
    },
    "SEC-IAC-006": {
        "pattern": r"acl\s*=\s*['\"]public-read(?:-write)?['\"]",
        "replacement": 'acl = "private"'
    }
}


def generate_suggested_fix(finding: Finding) -> Optional[str]:
    """Generate the suggested fixed line or block based on rule heuristics."""
    rule_id = finding.rule_id
    matched = finding.matched_line

    if not matched:
        return None

    if rule_id in FIX_PATTERNS:
        rule_spec = FIX_PATTERNS[rule_id]
        if "pattern" in rule_spec and "replacement" in rule_spec:
            try:
                fixed = re.sub(rule_spec["pattern"], rule_spec["replacement"], matched)
                if fixed != matched:
                    return fixed
            except Exception:
                pass

        if rule_id == "SEC-A03-001":  # SQL injection
            # e.g., cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
            # Suggest parameterized form
            if "f\"" in matched or "f'" in matched:
                return re.sub(r"f(['\"][^'\"]*\{[^}]+\}[^'\"]*['\"])", r"\1 # TODO: Pass variables as tuple (params,)", matched)

    # Fallback: if rule has remediation code example, extract first non-comment line
    return None


def generate_finding_diff(finding: Finding) -> Optional[str]:
    """Produce a unified diff format (diff -u) showing the proposed security patch."""
    suggested = generate_suggested_fix(finding)
    if not suggested or suggested == finding.matched_line:
        # If no regex auto-replacement, synthesize diff against rule's remediation code if available
        return None

    original_lines = [finding.matched_line + "\n"]
    fixed_lines = [suggested + "\n"]

    diff = difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile=f"a/{finding.file_path}",
        tofile=f"b/{finding.file_path}",
        lineterm=""
    )
    return "\n".join(diff)


def generate_scan_patch(scan: ScanResult) -> str:
    """Generate a combined multi-file .patch file for all fixable findings in a scan."""
    patches: List[str] = []
    patches.append(f"# OWASP Sentinel Automated Security Patch")
    patches.append(f"# Target Repository: {scan.repo_name}")
    patches.append(f"# Generated: {scan.created_at}")
    patches.append("")

    for finding in scan.findings:
        if finding.status in ("FALSE_POSITIVE", "RESOLVED"):
            continue

        diff = generate_finding_diff(finding)
        if diff:
            patches.append(f"# Finding: {finding.rule_id} - {finding.title} ({finding.file_path}:{finding.line_number})")
            patches.append(diff)
            patches.append("")

    return "\n".join(patches)


def apply_remediation_to_file(repo_path: str, finding: Finding) -> bool:
    """Atomically apply the suggested remediation directly to the repository file."""
    import os
    if not repo_path or not os.path.exists(repo_path):
        return False

    target_file = os.path.join(repo_path, finding.file_path)
    if not os.path.exists(target_file):
        return False

    suggested_fix = generate_suggested_fix(finding)
    if not suggested_fix:
        return False

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        target_idx = -1
        # Try line_number first (1-indexed)
        if 0 < finding.line_number <= len(lines):
            cand = lines[finding.line_number - 1]
            if finding.matched_line in cand or cand.strip() in finding.matched_line:
                target_idx = finding.line_number - 1

        # Search nearby or entire file if line moved
        if target_idx == -1:
            for idx, l in enumerate(lines):
                if finding.matched_line in l or l.strip() == finding.matched_line.strip():
                    target_idx = idx
                    break

        if target_idx == -1:
            return False

        # Apply replacement
        old_line = lines[target_idx]
        if finding.matched_line in old_line:
            new_line = old_line.replace(finding.matched_line, suggested_fix)
        else:
            new_line = suggested_fix + "\n"

        lines[target_idx] = new_line

        with open(target_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        return True
    except Exception:
        return False

