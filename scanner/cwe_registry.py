"""CWE Top 25 (2023/2024) Registry and Multi-Framework Standards Mapper.

Provides automated mapping between detected vulnerabilities and:
- MITRE CWE Top 25 Most Dangerous Software Weaknesses
- CIS Benchmarks (Docker, Kubernetes, Cloud IaC)
- OpenSSF / SLSA Supply Chain Security
- FOSS Open Source License Governance
- System & Memory Safety (Non-Web / Core Software)
- OWASP Top 10 Web (2021)
"""

from typing import Dict, Any, Optional, List

CWE_TOP_25_MAP: Dict[str, Dict[str, Any]] = {
    "CWE-787": {
        "rank": 1,
        "name": "Out-of-bounds Write",
        "score": 63.55,
        "description": "Software writes data past the end, or before the beginning, of the intended buffer.",
    },
    "CWE-79": {
        "rank": 2,
        "name": "Cross-site Scripting (XSS)",
        "score": 46.13,
        "description": "Improper neutralization of input during web page generation allows untrusted script execution.",
    },
    "CWE-89": {
        "rank": 3,
        "name": "SQL Injection",
        "score": 34.02,
        "description": "Improper neutralization of special elements in an SQL query allows query alteration and unauthorized data access.",
    },
    "CWE-416": {
        "rank": 4,
        "name": "Use After Free",
        "score": 28.52,
        "description": "Referencing memory after it has been freed can lead to program crash, data corruption, or code execution.",
    },
    "CWE-78": {
        "rank": 5,
        "name": "OS Command Injection",
        "score": 26.31,
        "description": "Improper neutralization of special elements in an OS command allows executing arbitrary host commands.",
    },
    "CWE-20": {
        "rank": 6,
        "name": "Improper Input Validation",
        "score": 23.47,
        "description": "Product receives input or data, but does not validate or incorrectly validates that input satisfies requirements.",
    },
    "CWE-125": {
        "rank": 7,
        "name": "Out-of-bounds Read",
        "score": 21.84,
        "description": "Software reads data past the end, or before the beginning, of the intended buffer, leaking confidential memory.",
    },
    "CWE-22": {
        "rank": 8,
        "name": "Path Traversal",
        "score": 20.73,
        "description": "Limitation of pathname to a restricted directory fails, allowing access to arbitrary filesystem files via '../'.",
    },
    "CWE-352": {
        "rank": 9,
        "name": "Cross-Site Request Forgery (CSRF)",
        "score": 19.34,
        "description": "Web server does not verify that a request was intentionally initiated by the authenticated user.",
    },
    "CWE-434": {
        "rank": 10,
        "name": "Unrestricted Upload of Dangerous File Type",
        "score": 18.29,
        "description": "Product allows an attacker to upload files of dangerous types that can be automatically processed within the environment.",
    },
    "CWE-862": {
        "rank": 11,
        "name": "Missing Authorization",
        "score": 17.51,
        "description": "Software does not perform an authorization check when an actor attempts to access a restricted resource.",
    },
    "CWE-476": {
        "rank": 12,
        "name": "NULL Pointer Dereference",
        "score": 16.92,
        "description": "Application dereferences a pointer that evaluates to NULL, resulting in application crash or denial of service.",
    },
    "CWE-287": {
        "rank": 13,
        "name": "Improper Authentication",
        "score": 16.03,
        "description": "Actor claims to have a given identity, but software fails to properly prove the claim is valid.",
    },
    "CWE-190": {
        "rank": 14,
        "name": "Integer Overflow or Wraparound",
        "score": 15.65,
        "description": "Software performs an integer calculation that can produce a value exceeding integer limits, causing memory corruption or logic bypass.",
    },
    "CWE-502": {
        "rank": 15,
        "name": "Deserialization of Untrusted Data",
        "score": 14.88,
        "description": "Application deserializes untrusted data without sufficient verification, leading to arbitrary remote code execution.",
    },
    "CWE-77": {
        "rank": 16,
        "name": "Command Injection",
        "score": 13.92,
        "description": "Software constructs all or part of a command using untrusted input from an upstream component.",
    },
    "CWE-119": {
        "rank": 17,
        "name": "Improper Restriction of Operations within Buffer Bounds",
        "score": 12.85,
        "description": "Operations on a memory buffer do not verify boundaries, leading to memory alteration or control-flow hijacking.",
    },
    "CWE-798": {
        "rank": 18,
        "name": "Hard-coded Credentials",
        "score": 11.76,
        "description": "Software contains hard-coded secret authentication tokens, private keys, or passwords.",
    },
    "CWE-918": {
        "rank": 19,
        "name": "Server-Side Request Forgery (SSRF)",
        "score": 10.94,
        "description": "Web server accepts a target URL from user input and makes a backend HTTP request without validation.",
    },
    "CWE-306": {
        "rank": 20,
        "name": "Missing Authentication for Critical Function",
        "score": 9.87,
        "description": "Software does not require authentication for sensitive functions such as administration or data deletion.",
    },
    "CWE-362": {
        "rank": 21,
        "name": "Concurrent Execution Race Condition",
        "score": 8.76,
        "description": "Concurrent execution using a shared resource without proper synchronization introduces unexpected state changes or TOCTOU flaws.",
    },
    "CWE-269": {
        "rank": 22,
        "name": "Improper Privilege Management",
        "score": 7.95,
        "description": "Software fails to properly assign, modify, track, or revoke privileges for an actor or process.",
    },
    "CWE-94": {
        "rank": 23,
        "name": "Code Injection",
        "score": 7.21,
        "description": "Software constructs all or part of a code segment using untrusted input, executing unauthorized instructions.",
    },
    "CWE-863": {
        "rank": 24,
        "name": "Incorrect Authorization",
        "score": 6.84,
        "description": "Software performs an authorization check, but specifies an incorrect or incomplete set of permissions.",
    },
    "CWE-276": {
        "rank": 25,
        "name": "Incorrect Default Permissions",
        "score": 6.42,
        "description": "Default permissions on files, directories, or registry keys grant excessive access (e.g. world-writable 0777).",
    },
}


def get_cwe_top25_rank(cwe: str) -> Optional[int]:
    """Return the 1-based rank in MITRE CWE Top 25 if present, else None."""
    if not cwe:
        return None
    cwe_norm = cwe.strip().upper()
    if not cwe_norm.startswith("CWE-") and cwe_norm.isdigit():
        cwe_norm = f"CWE-{cwe_norm}"
    info = CWE_TOP_25_MAP.get(cwe_norm)
    return info["rank"] if info else None


def get_cwe_details(cwe: str) -> Optional[Dict[str, Any]]:
    """Return full metadata for a CWE if in CWE Top 25."""
    if not cwe:
        return None
    cwe_norm = cwe.strip().upper()
    if not cwe_norm.startswith("CWE-") and cwe_norm.isdigit():
        cwe_norm = f"CWE-{cwe_norm}"
    return CWE_TOP_25_MAP.get(cwe_norm)


def resolve_frameworks(rule_id: str, category: str, cwe: str) -> List[str]:
    """Compute all matching security frameworks and standards for a finding or rule."""
    frameworks: List[str] = []

    # 1. OWASP Top 10 Web
    if any(category.startswith(p) for p in ("A0", "A10", "API")):
        frameworks.append("OWASP Top 10")

    # 2. CWE Top 25
    rank = get_cwe_top25_rank(cwe)
    if rank is not None or "CWE-Top25" in category:
        frameworks.append("CWE Top 25")

    # 3. CIS Benchmarks (Container & Cloud IaC)
    if rule_id.startswith("CIS-") or rule_id.startswith("SEC-IAC-") or "CIS-" in category:
        frameworks.append("CIS Benchmarks")

    # 4. OpenSSF / SLSA Supply Chain
    if rule_id.startswith("SLSA-") or "SLSA" in category or "Supply-Chain" in category:
        frameworks.append("OpenSSF / SLSA")

    # 5. FOSS License Governance
    if rule_id.startswith("LIC-") or "FOSS" in category or "License" in category:
        frameworks.append("FOSS Governance")

    # 6. System Safety & Concurrency
    if "System-Safety" in category or rule_id.startswith("SYS-") or cwe in ("CWE-476", "CWE-190", "CWE-362", "CWE-276", "CWE-377", "CWE-676"):
        frameworks.append("System Safety")

    # 7. Secrets & Key Protection (NIST SP 800-57)
    if "A02" in category or cwe == "CWE-798" or rule_id.startswith("SEC-SECRET-"):
        frameworks.append("Secrets & Key Protection")

    if not frameworks:
        frameworks.append("General Security")

    return frameworks
