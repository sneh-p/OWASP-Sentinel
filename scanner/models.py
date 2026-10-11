"""Data models for OWASP Sentinel security scanner."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime, timezone


class SecurityCategory(str, Enum):
    # OWASP Top 10 (2021) Web Application Security
    A01 = "A01:2021-Broken Access Control"
    A02 = "A02:2021-Cryptographic Failures"
    A03 = "A03:2021-Injection"
    A04 = "A04:2021-Insecure Design"
    A05 = "A05:2021-Security Misconfiguration"
    A06 = "A06:2021-Vulnerable and Outdated Components"
    A07 = "A07:2021-Identification and Authentication Failures"
    A08 = "A08:2021-Software and Data Integrity Failures"
    A09 = "A09:2021-Security Logging and Monitoring Failures"
    A10 = "A10:2021-Server-Side Request Forgery (SSRF)"

    # Enterprise Multi-Standard Frameworks Beyond OWASP
    CWE_TOP25 = "CWE-Top25:Most Dangerous Software Weaknesses"
    CIS_CONTAINER = "CIS-Cloud-Container:Container & Cloud Infrastructure Security"
    SUPPLY_CHAIN = "SLSA-Supply-Chain:CI/CD & Supply Chain Security"
    FOSS_LICENSE = "FOSS-Governance:Open Source License & Legal Compliance"
    SYSTEM_SAFETY = "System-Safety:Memory, Concurrency & Resource Safety"

    @property
    def short_code(self) -> str:
        return self.value.split(":")[0]

    @property
    def title(self) -> str:
        return self.value.split("-", 1)[1] if "-" in self.value else self.value


# Backwards compatibility alias
OWASPCategory = SecurityCategory


CATEGORY_METADATA = {
    # OWASP Top 10
    "A01": {
        "code": "A01:2021",
        "name": "Broken Access Control",
        "badge_color": "bg-red-500/20 text-red-400 border-red-500/30",
        "description": "Failures that allow unauthorized information disclosure, modification, or destruction of data outside the user's intended permissions.",
        "icon": "shield-alert",
        "framework": "OWASP Top 10"
    },
    "A02": {
        "code": "A02:2021",
        "name": "Cryptographic Failures",
        "badge_color": "bg-amber-500/20 text-amber-400 border-amber-500/30",
        "description": "Exposure of sensitive data or compromise of keys, weak cryptographic algorithms, or missing TLS verification.",
        "icon": "key-round",
        "framework": "OWASP Top 10"
    },
    "A03": {
        "code": "A03:2021",
        "name": "Injection",
        "badge_color": "bg-rose-500/20 text-rose-400 border-rose-500/30",
        "description": "Flaws allowing untrusted user data to be interpreted as system commands, queries (SQL, NoSQL, OS command), or scripts (XSS).",
        "icon": "terminal",
        "framework": "OWASP Top 10"
    },
    "A04": {
        "code": "A04:2021",
        "name": "Insecure Design",
        "badge_color": "bg-purple-500/20 text-purple-400 border-purple-500/30",
        "description": "Architectural and design flaws, lack of threat modeling, absence of security controls by design.",
        "icon": "drafting-compass",
        "framework": "OWASP Top 10"
    },
    "A05": {
        "code": "A05:2021",
        "name": "Security Misconfiguration",
        "badge_color": "bg-orange-500/20 text-orange-400 border-orange-500/30",
        "description": "Default configurations, verbose error messages exposing stack traces, misconfigured HTTP headers, or enabled debug modes.",
        "icon": "settings",
        "framework": "OWASP Top 10"
    },
    "A06": {
        "code": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "badge_color": "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
        "description": "Using client or server components with known CVE vulnerabilities or unsupported dependencies.",
        "icon": "package-x",
        "framework": "OWASP Top 10"
    },
    "A07": {
        "code": "A07:2021",
        "name": "Identification and Authentication Failures",
        "badge_color": "bg-blue-500/20 text-blue-400 border-blue-500/30",
        "description": "Permitting credential stuffing, brute force, weak session management, or missing secure cookie attributes.",
        "icon": "user-x",
        "framework": "OWASP Top 10"
    },
    "A08": {
        "code": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "badge_color": "bg-indigo-500/20 text-indigo-400 border-indigo-500/30",
        "description": "Code and infrastructure that do not protect against integrity violations, such as insecure deserialization and unverified plugins/libraries.",
        "icon": "file-code",
        "framework": "OWASP Top 10"
    },
    "A09": {
        "code": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "badge_color": "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
        "description": "Failures in logging critical security events, swallowing exceptions silently, or logging sensitive personal data.",
        "icon": "activity",
        "framework": "OWASP Top 10"
    },
    "A10": {
        "code": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "badge_color": "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
        "description": "Web applications fetching a remote resource without validating the user-supplied URL.",
        "icon": "globe",
        "framework": "OWASP Top 10"
    },
    # Beyond OWASP: Multi-Framework Categories
    "CWE-Top25": {
        "code": "CWE-Top25",
        "name": "CWE Top 25 Most Dangerous Weaknesses",
        "badge_color": "bg-fuchsia-500/20 text-fuchsia-400 border-fuchsia-500/30",
        "description": "Critical system, pointer, memory safety, and logic vulnerabilities from the MITRE CWE Top 25 list.",
        "icon": "bug",
        "framework": "CWE Top 25"
    },
    "CIS-Cloud-Container": {
        "code": "CIS-Cloud-Container",
        "name": "CIS Benchmarks: Cloud & Container Security",
        "badge_color": "bg-sky-500/20 text-sky-400 border-sky-500/30",
        "description": "CIS Docker & Kubernetes Benchmarks, container hardening, rootless execution, and cloud IaC security.",
        "icon": "box",
        "framework": "CIS Benchmarks"
    },
    "SLSA-Supply-Chain": {
        "code": "SLSA-Supply-Chain",
        "name": "SLSA & OpenSSF Supply Chain Security",
        "badge_color": "bg-violet-500/20 text-violet-400 border-violet-500/30",
        "description": "Pipeline integrity, pinned action hashes, secret isolation, and build artifact provenance.",
        "icon": "git-merge",
        "framework": "OpenSSF / SLSA"
    },
    "FOSS-Governance": {
        "code": "FOSS-Governance",
        "name": "FOSS License & Legal Compliance",
        "badge_color": "bg-amber-500/20 text-amber-400 border-amber-500/30",
        "description": "Open source license compatibility, copyleft contamination risks (GPL/AGPL), and commercial distribution safety.",
        "icon": "scale",
        "framework": "FOSS Governance"
    },
    "System-Safety": {
        "code": "System-Safety",
        "name": "System Safety & Resource Management",
        "badge_color": "bg-teal-500/20 text-teal-400 border-teal-500/30",
        "description": "Race conditions (TOCTOU), uncontrolled resource allocation, unhandled exceptions, and unsafe libc APIs.",
        "icon": "cpu",
        "framework": "System Safety"
    }
}

OWASP_METADATA = CATEGORY_METADATA


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        weights = {
            "CRITICAL": 15,
            "HIGH": 8,
            "MEDIUM": 4,
            "LOW": 1,
            "INFO": 0,
        }
        return weights.get(self.value, 1)

    @property
    def badge_class(self) -> str:
        styles = {
            "CRITICAL": "bg-red-500/20 text-red-300 border-red-500/40",
            "HIGH": "bg-orange-500/20 text-orange-300 border-orange-500/40",
            "MEDIUM": "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
            "LOW": "bg-blue-500/20 text-blue-300 border-blue-500/40",
            "INFO": "bg-slate-500/20 text-slate-300 border-slate-500/40",
        }
        return styles.get(self.value, "bg-slate-500/20 text-slate-300 border-slate-500/40")


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    rule_id: str = ""
    title: str = ""
    category: str = ""
    severity: str = "MEDIUM"
    cwe: str = ""
    file_path: str = ""
    line_number: int = 1
    column_number: int = 0
    matched_line: str = ""
    code_snippet: str = ""
    description: str = ""
    remediation: str = ""
    status: str = "OPEN"
    notes: str = ""
    cwe_rank: Optional[int] = None
    frameworks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Rule:
    id: str
    title: str
    category: SecurityCategory
    severity: Severity
    cwe: str
    languages: List[str]  # e.g., ['py', 'js', 'ts', 'java', 'go', 'php', 'json', 'txt', '*']
    description: str
    remediation: str
    patterns: List[str] = field(default_factory=list)
    remediation_code: str = ""
    standard: str = "OWASP Top 10"
    cwe_rank: Optional[int] = None
    frameworks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        cat_val = self.category.value if hasattr(self.category, "value") else str(self.category)
        cat_code = self.category.short_code if hasattr(self.category, "short_code") else cat_val.split(":")[0]
        cat_title = self.category.title if hasattr(self.category, "title") else cat_val
        return {
            "id": self.id,
            "title": self.title,
            "category": cat_val,
            "category_code": cat_code,
            "category_name": cat_title,
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "cwe": self.cwe,
            "languages": self.languages,
            "description": self.description,
            "remediation": self.remediation,
            "remediation_code": self.remediation_code,
            "standard": self.standard,
            "cwe_rank": self.cwe_rank,
            "frameworks": self.frameworks,
        }


@dataclass
class ScanResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    repo_name: str = ""
    repo_path: str = ""
    source_type: str = "local"  # 'git', 'upload', 'local', 'sample'
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_seconds: float = 0.0
    total_files: int = 0
    scanned_files: int = 0
    lines_of_code: int = 0
    score: int = 100
    grade: str = "A+"
    status: str = "completed"  # 'running', 'completed', 'failed'
    error_message: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    counts_by_severity: Dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    })
    counts_by_category: Dict[str, int] = field(default_factory=dict)
    source_url: str = ""
    branch: str = ""
    subfolder: str = ""
    folder_counts: Dict[str, int] = field(default_factory=dict)

    def calculate_metrics(self):
        """Calculate overall security score, grade, and finding counts."""
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        cat_counts = {f"A{i:02d}": 0 for i in range(1, 11)}

        penalty = 0
        for f in self.findings:
            if f.status == FindingStatus.FALSE_POSITIVE.value:
                continue
            sev = f.severity.upper()
            if sev in sev_counts:
                sev_counts[sev] += 1
            else:
                sev_counts[sev] = 1

            cat_prefix = f.category.split(":")[0] if ":" in f.category else f.category[:3]
            cat_counts[cat_prefix] = cat_counts.get(cat_prefix, 0) + 1

            try:
                penalty += Severity[sev].weight
            except KeyError:
                penalty += 2

        self.counts_by_severity = sev_counts
        self.counts_by_category = cat_counts

        calculated_score = max(0, 100 - penalty)
        self.score = calculated_score

        if calculated_score >= 95:
            self.grade = "A+"
        elif calculated_score >= 85:
            self.grade = "A"
        elif calculated_score >= 70:
            self.grade = "B"
        elif calculated_score >= 55:
            self.grade = "C"
        elif calculated_score >= 40:
            self.grade = "D"
        else:
            self.grade = "F"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d
