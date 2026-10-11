"""Dependency checker for known vulnerable and outdated components (OWASP A06:2021)."""

import re
import json
from typing import List, Dict, Any, Optional
from packaging import version
from .models import Finding, OWASPCategory, Severity

# Curated database of high-profile CVEs in common dependencies
KNOWN_VULNERABLE_PACKAGES: Dict[str, List[Dict[str, Any]]] = {
    # Python ecosystem
    "flask": [
        {
            "cve": "CVE-2023-30861",
            "affected": "<2.2.5",
            "fixed": "2.2.5",
            "severity": Severity.HIGH,
            "title": "Flask Session Cookie Secret Key Disclosure / Weak Key",
            "description": "Flask versions prior to 2.2.5 did not set Vary: Cookie header for cached responses when a session was accessed, potentially leaking session data.",
            "remediation": "Upgrade Flask to version 2.2.5 or higher."
        }
    ],
    "django": [
        {
            "cve": "CVE-2023-43665",
            "affected": "<4.2.6",
            "fixed": "4.2.6",
            "severity": Severity.HIGH,
            "title": "Django Denial of Service via Truncate HTML Words",
            "description": "Django before 4.2.6 is vulnerable to ReDoS in django.utils.text.Truncator.",
            "remediation": "Upgrade Django to version 4.2.6 or 5.0+."
        },
        {
            "cve": "CVE-2022-34265",
            "affected": "<3.2.14",
            "fixed": "3.2.14",
            "severity": Severity.CRITICAL,
            "title": "Django SQL Injection via Trunc() / Extract()",
            "description": "Arguments passed to Trunc() and Extract() database functions were not properly escaped, permitting SQL injection.",
            "remediation": "Upgrade Django to version 3.2.14 or later."
        }
    ],
    "requests": [
        {
            "cve": "CVE-2023-32681",
            "affected": "<2.31.0",
            "fixed": "2.31.0",
            "severity": Severity.MEDIUM,
            "title": "Requests Proxy-Authorization Header Leakage on HTTPS Redirection",
            "description": "Requests prior to 2.31.0 forwards Proxy-Authorization header during HTTPS-to-HTTP redirects, exposing credentials.",
            "remediation": "Upgrade requests to >= 2.31.0."
        }
    ],
    "pyyaml": [
        {
            "cve": "CVE-2020-14343",
            "affected": "<5.4",
            "fixed": "5.4",
            "severity": Severity.CRITICAL,
            "title": "PyYAML Insecure Deserialization via FullLoader",
            "description": "PyYAML before 5.4 lacks proper type checks during loading, permitting arbitrary code execution via custom tags.",
            "remediation": "Upgrade PyYAML to >= 5.4 and always use yaml.safe_load()."
        }
    ],
    "urllib3": [
        {
            "cve": "CVE-2023-45803",
            "affected": "<2.0.7",
            "fixed": "2.0.7",
            "severity": Severity.HIGH,
            "title": "urllib3 Request Body De-synchronization / HTTP Request Smuggling",
            "description": "urllib3 before 2.0.7 failed to strip Authorization headers during cross-origin redirects under certain conditions.",
            "remediation": "Upgrade urllib3 to >= 2.0.7."
        }
    ],
    "cryptography": [
        {
            "cve": "CVE-2023-49083",
            "affected": "<41.0.6",
            "fixed": "41.0.6",
            "severity": Severity.HIGH,
            "title": "Null pointer dereference when loading PKCS#7 certificate files",
            "description": "Calling cryptography.hazmat.primitives.serialization.pkcs7.load_pem_pkcs7_certificates on corrupted certificates crashes the interpreter.",
            "remediation": "Upgrade cryptography to >= 41.0.6."
        }
    ],
    "werkzeug": [
        {
            "cve": "CVE-2023-46136",
            "affected": "<3.0.1",
            "fixed": "3.0.1",
            "severity": Severity.HIGH,
            "title": "Werkzeug High Memory Usage / ReDoS in Multipart Parser",
            "description": "Werkzeug before 3.0.1 multipart parser consumes excessive memory when handling maliciously crafted headers.",
            "remediation": "Upgrade werkzeug to >= 3.0.1."
        }
    ],
    "pillow": [
        {
            "cve": "CVE-2023-50447",
            "affected": "<10.2.0",
            "fixed": "10.2.0",
            "severity": Severity.CRITICAL,
            "title": "Pillow Arbitrary Code Execution via ImageMath.eval",
            "description": "Pillow prior to 10.2.0 allowed arbitrary code execution via builtins access in ImageMath.eval.",
            "remediation": "Upgrade Pillow to >= 10.2.0."
        }
    ],

    # JavaScript / Node.js ecosystem
    "lodash": [
        {
            "cve": "CVE-2021-23337",
            "affected": "<4.17.21",
            "fixed": "4.17.21",
            "severity": Severity.HIGH,
            "title": "Lodash Prototype Pollution via template function",
            "description": "Lodash before 4.17.21 allows attackers to cause prototype pollution via malicious template interpolation options.",
            "remediation": "Upgrade lodash to >= 4.17.21."
        }
    ],
    "axios": [
        {
            "cve": "CVE-2023-45857",
            "affected": "<1.6.0",
            "fixed": "1.6.0",
            "severity": Severity.HIGH,
            "title": "Axios Cross-Site Request Forgery / SSRF via follow-redirects",
            "description": "Axios before 1.6.0 does not clear sensitive headers when following cross-origin redirects.",
            "remediation": "Upgrade axios to >= 1.6.0."
        }
    ],
    "express": [
        {
            "cve": "CVE-2024-29041",
            "affected": "<4.19.2",
            "fixed": "4.19.2",
            "severity": Severity.HIGH,
            "title": "Express Open Redirect / Improper URL Validation",
            "description": "Express before 4.19.2 handles redirects without sufficiently checking URL encoding.",
            "remediation": "Upgrade express to >= 4.19.2."
        }
    ],
    "jsonwebtoken": [
        {
            "cve": "CVE-2022-23529",
            "affected": "<9.0.0",
            "fixed": "9.0.0",
            "severity": Severity.CRITICAL,
            "title": "jsonwebtoken Arbitrary Code Execution via jwt.verify",
            "description": "jsonwebtoken before 9.0.0 is vulnerable to arbitrary code execution if untrusted user input is passed as the secret or key parameter.",
            "remediation": "Upgrade jsonwebtoken to >= 9.0.0."
        }
    ]
}


def parse_requirement_version(spec: str) -> Optional[str]:
    """Extract clean version number from dependency string (e.g. 'flask==2.0.1' -> '2.0.1')."""
    match = re.search(r"==\s*([0-9a-zA-Z\.\-]+)", spec)
    if match:
        return match.group(1).strip()
    match = re.search(r"<=\s*([0-9a-zA-Z\.\-]+)", spec)
    if match:
        return match.group(1).strip()
    match = re.search(r"~=\s*([0-9a-zA-Z\.\-]+)", spec)
    if match:
        return match.group(1).strip()
    return None


def is_version_vulnerable(installed_str: str, affected_rule: str) -> bool:
    """Check if installed version satisfies vulnerability condition like '<2.2.5'."""
    try:
        inst_v = version.parse(installed_str)
        if affected_rule.startswith("<="):
            target_v = version.parse(affected_rule[2:])
            return inst_v <= target_v
        elif affected_rule.startswith("<"):
            target_v = version.parse(affected_rule[1:])
            return inst_v < target_v
        elif affected_rule.startswith("=="):
            target_v = version.parse(affected_rule[2:])
            return inst_v == target_v
    except Exception:
        pass
    return False


def scan_requirements_txt(content: str, file_path: str) -> List[Finding]:
    findings = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        clean_line = line.strip().split("#")[0].strip()
        if not clean_line:
            continue

        # Check for unpinned dependency
        if re.match(r"^[a-zA-Z0-9_\-]+$", clean_line) or clean_line.endswith(">=*"):
            findings.append(Finding(
                rule_id="SEC-A06-003",
                title=f"Unpinned Dependency Version: '{clean_line}'",
                category=OWASPCategory.A06.value,
                severity=Severity.LOW.value,
                cwe="CWE-1104",
                file_path=file_path,
                line_number=idx,
                matched_line=line,
                code_snippet=line,
                description=f"Dependency '{clean_line}' has no pinned version. Building or deploying may pull in breaking changes or compromised upstream releases.",
                remediation=f"Pin dependencies to tested, exact versions (e.g., '{clean_line}==X.Y.Z') and verify with hash checking.",
            ))

        # Check against known CVEs
        for pkg_name, cve_list in KNOWN_VULNERABLE_PACKAGES.items():
            pattern = rf"^{re.escape(pkg_name)}\s*(?:==|<=|~=)\s*([0-9a-zA-Z\.\-]+)"
            match = re.match(pattern, clean_line, re.IGNORECASE)
            if match:
                inst_ver = match.group(1)
                for vuln in cve_list:
                    if is_version_vulnerable(inst_ver, vuln["affected"]):
                        snippet = f"Line {idx}: {line}\n# Vulnerable package: {pkg_name} {inst_ver} ({vuln['affected']})\n# {vuln['cve']}"
                        findings.append(Finding(
                            rule_id="SEC-A06-001",
                            title=f"{vuln['title']} ({vuln['cve']})",
                            category=OWASPCategory.A06.value,
                            severity=vuln["severity"].value,
                            cwe="CWE-1395",
                            file_path=file_path,
                            line_number=idx,
                            matched_line=line,
                            code_snippet=snippet,
                            description=f"{vuln['description']} (Installed: {inst_ver}, Affected: {vuln['affected']})",
                            remediation=f"{vuln['remediation']} Recommended fixed version: >= {vuln['fixed']}",
                        ))
    return findings


def scan_package_json(content: str, file_path: str) -> List[Finding]:
    findings = []
    try:
        data = json.loads(content)
    except Exception:
        return findings

    all_deps = {}
    if "dependencies" in data and isinstance(data["dependencies"], dict):
        all_deps.update(data["dependencies"])
    if "devDependencies" in data and isinstance(data["devDependencies"], dict):
        all_deps.update(data["devDependencies"])

    lines = content.splitlines()

    for pkg_name, ver_spec in all_deps.items():
        clean_ver = re.sub(r"[\^~>=<]", "", ver_spec).strip()
        if not clean_ver:
            continue

        if pkg_name in KNOWN_VULNERABLE_PACKAGES:
            for vuln in KNOWN_VULNERABLE_PACKAGES[pkg_name]:
                if is_version_vulnerable(clean_ver, vuln["affected"]):
                    line_no = 1
                    matched_l = f'"{pkg_name}": "{ver_spec}"'
                    for idx, line in enumerate(lines, start=1):
                        if f'"{pkg_name}"' in line:
                            line_no = idx
                            matched_l = line.strip()
                            break

                    findings.append(Finding(
                        rule_id="SEC-A06-002",
                        title=f"{vuln['title']} ({vuln['cve']})",
                        category=OWASPCategory.A06.value,
                        severity=vuln["severity"].value,
                        cwe="CWE-1395",
                        file_path=file_path,
                        line_number=line_no,
                        matched_line=matched_l,
                        code_snippet=matched_l,
                        description=f"{vuln['description']} (Installed: {clean_ver}, Affected: {vuln['affected']})",
                        remediation=f"{vuln['remediation']} Recommended fixed version: >= {vuln['fixed']}",
                    ))
    return findings
