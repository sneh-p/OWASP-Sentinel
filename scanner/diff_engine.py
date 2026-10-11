"""Scan Diff & Regression Engine for comparing two security scans."""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from .models import ScanResult, Finding


@dataclass
class ScanComparison:
    base_scan_id: str
    target_scan_id: str
    base_repo_name: str
    target_repo_name: str
    base_date: str
    target_date: str
    base_score: int
    target_score: int
    score_delta: int
    base_grade: str
    target_grade: str
    new_findings: List[Finding] = field(default_factory=list)
    fixed_findings: List[Finding] = field(default_factory=list)
    persistent_findings: List[Finding] = field(default_factory=list)

    @property
    def is_improved(self) -> bool:
        return self.score_delta > 0 or (len(self.fixed_findings) > 0 and len(self.new_findings) == 0)

    @property
    def is_regressed(self) -> bool:
        return self.score_delta < 0 or len(self.new_findings) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_scan_id": self.base_scan_id,
            "target_scan_id": self.target_scan_id,
            "base_repo_name": self.base_repo_name,
            "target_repo_name": self.target_repo_name,
            "base_date": self.base_date,
            "target_date": self.target_date,
            "base_score": self.base_score,
            "target_score": self.target_score,
            "score_delta": self.score_delta,
            "base_grade": self.base_grade,
            "target_grade": self.target_grade,
            "is_improved": self.is_improved,
            "is_regressed": self.is_regressed,
            "new_count": len(self.new_findings),
            "fixed_count": len(self.fixed_findings),
            "persistent_count": len(self.persistent_findings),
            "new_findings": [f.to_dict() for f in self.new_findings],
            "fixed_findings": [f.to_dict() for f in self.fixed_findings],
            "persistent_findings": [f.to_dict() for f in self.persistent_findings],
        }


def _finding_fingerprint(finding: Finding) -> str:
    """Generate a stable fingerprint to match findings across scans."""
    clean_line = "".join(finding.matched_line.split()) if finding.matched_line else ""
    return f"{finding.rule_id}::{finding.file_path}::{clean_line}"


def compare_scans(base_scan: ScanResult, target_scan: ScanResult) -> ScanComparison:
    """Compare two scans to detect new vulnerabilities, fixed bugs, and regressions."""
    base_map = {_finding_fingerprint(f): f for f in base_scan.findings if f.status != "FALSE_POSITIVE"}
    target_map = {_finding_fingerprint(f): f for f in target_scan.findings if f.status != "FALSE_POSITIVE"}

    new_findings: List[Finding] = []
    persistent_findings: List[Finding] = []
    fixed_findings: List[Finding] = []

    # Check target findings against base
    for fp, t_finding in target_map.items():
        if fp in base_map:
            persistent_findings.append(t_finding)
        else:
            new_findings.append(t_finding)

    # Check base findings for ones missing in target (fixed)
    for fp, b_finding in base_map.items():
        if fp not in target_map:
            fixed_findings.append(b_finding)

    score_delta = target_scan.score - base_scan.score

    return ScanComparison(
        base_scan_id=base_scan.id,
        target_scan_id=target_scan.id,
        base_repo_name=base_scan.repo_name,
        target_repo_name=target_scan.repo_name,
        base_date=base_scan.created_at,
        target_date=target_scan.created_at,
        base_score=base_scan.score,
        target_score=target_scan.score,
        score_delta=score_delta,
        base_grade=base_scan.grade,
        target_grade=target_scan.grade,
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        persistent_findings=persistent_findings
    )
