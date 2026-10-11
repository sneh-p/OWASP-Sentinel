"""OWASP A06:2021 - Vulnerable and Outdated Components Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A06-001",
        title="Vulnerable Python Dependency Identified (Known CVE)",
        category=OWASPCategory.A06,
        severity=Severity.HIGH,
        cwe="CWE-1395",
        languages=["txt"],
        description="A package declared in requirements.txt or Pipfile has a published Common Vulnerabilities and Exposures (CVE) identifier with known exploit techniques.",
        remediation="Upgrade the affected dependency to the specified fixed version or apply security patches recommended by vendor advisories.",
        remediation_code="""# Update requirements.txt to latest patched version:
# Example:
# Flask>=2.2.5
# requests>=2.31.0
# django>=4.2.8""",
        patterns=[]
    ),
    Rule(
        id="SEC-A06-002",
        title="Vulnerable JavaScript/Node.js Dependency Identified (Known CVE)",
        category=OWASPCategory.A06,
        severity=Severity.HIGH,
        cwe="CWE-1395",
        languages=["json"],
        description="A package specified in package.json or package-lock.json is known to be vulnerable to attacks like prototype pollution, remote code execution, or SSRF.",
        remediation="Run 'npm audit fix' or update the package version in package.json to the fixed release.",
        remediation_code="""# Update package.json:
# "lodash": "^4.17.21"
# "axios": "^1.6.0"
# "express": "^4.19.2" """,
        patterns=[]
    ),
    Rule(
        id="SEC-A06-003",
        title="Unpinned / Wildcard Dependency Version",
        category=OWASPCategory.A06,
        severity=Severity.LOW,
        cwe="CWE-1104",
        languages=["txt", "json"],
        description="Specifying open or unpinned versions (such as 'package=*' or 'package' without version) allows unexpected downstream package updates that could break builds or introduce malicious packages via dependency confusion / hijacking.",
        remediation="Pin exact dependency versions using strict version pins (==) and cryptographic checksum hashes.",
        remediation_code="""# Pin exact versions:
requests==2.31.0
flask==3.0.0""",
        patterns=[]
    ),
    Rule(
        id="SEC-A06-004",
        title="Unpinned or Latest Docker Base Image",
        category=OWASPCategory.A06,
        severity=Severity.MEDIUM,
        cwe="CWE-1104",
        languages=["dockerfile", "Dockerfile"],
        description="Using ':latest' or omitting the tag on Docker base images can unpredictably introduce breaking vulnerabilities or untested upstream modifications.",
        remediation="Pin base images to a specific version or immutable digest SHA256 (e.g. python:3.11.7-alpine or python@sha256:...).",
        remediation_code="""# Pin exact image digest or version tag:
FROM python:3.11.8-slim-bookworm""",
        patterns=[
            r"^FROM\s+[a-zA-Z0-9_\-\./]+:latest\b",
            r"^FROM\s+[a-zA-Z0-9_\-\./]+(?!\s*:\s*[a-zA-Z0-9_\-\.]|\s+AS|\s+as)\s*$",
        ]
    )
]
