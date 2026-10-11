"""Policy-as-Code Quality Gate Engine for OWASP Sentinel.

Provides automated build break / merge gate decisions for CI/CD pipelines
and devsecops workflows based on configurable security thresholds.
"""

from typing import Dict, Any, List, Optional
from .models import ScanResult, Severity

QUALITY_GATE_PRESETS: Dict[str, Dict[str, Any]] = {
    "strict": {
        "name": "Enterprise Strict",
        "description": "Zero tolerance for Critical and High vulnerabilities. Enforces secrets elimination and minimum score of 90.",
        "max_critical": 0,
        "max_high": 0,
        "min_score": 90,
        "disallow_secrets": True,
        "disallow_unpinned": True,
    },
    "standard": {
        "name": "Standard Recommended",
        "description": "Zero Critical vulnerabilities, maximum 2 High issues, zero hardcoded secrets, and minimum score of 75.",
        "max_critical": 0,
        "max_high": 2,
        "min_score": 75,
        "disallow_secrets": True,
        "disallow_unpinned": False,
    },
    "permissive": {
        "name": "Permissive / Legacy",
        "description": "Permits up to 1 Critical and 5 High issues, minimum score 50. Suitable for brownfield legacy transitions.",
        "max_critical": 1,
        "max_high": 5,
        "min_score": 50,
        "disallow_secrets": False,
        "disallow_unpinned": False,
    }
}


class QualityGateEngine:
    def __init__(self, preset_name: str = "standard", custom_policy: Optional[Dict[str, Any]] = None):
        self.preset_name = preset_name
        self.policy = custom_policy or QUALITY_GATE_PRESETS.get(preset_name, QUALITY_GATE_PRESETS["standard"])

    def evaluate(self, scan: ScanResult) -> Dict[str, Any]:
        """Evaluate a scan result against the configured quality gate policy."""
        violations: List[Dict[str, str]] = []
        passed_checks: List[Dict[str, str]] = []

        crit_count = scan.counts_by_severity.get("CRITICAL", 0)
        high_count = scan.counts_by_severity.get("HIGH", 0)
        score = scan.score

        # Check 1: Critical threshold
        max_crit = self.policy.get("max_critical", 0)
        if crit_count > max_crit:
            violations.append({
                "rule": "Max Critical Findings",
                "message": f"Found {crit_count} Critical vulnerabilities (policy allows maximum {max_crit})."
            })
        else:
            passed_checks.append({
                "rule": "Max Critical Findings",
                "message": f"{crit_count} Critical vulnerabilities within threshold ({max_crit})."
            })

        # Check 2: High threshold
        max_high = self.policy.get("max_high", 2)
        if high_count > max_high:
            violations.append({
                "rule": "Max High Findings",
                "message": f"Found {high_count} High vulnerabilities (policy allows maximum {max_high})."
            })
        else:
            passed_checks.append({
                "rule": "Max High Findings",
                "message": f"{high_count} High vulnerabilities within threshold ({max_high})."
            })

        # Check 3: Minimum Security Score
        min_score = self.policy.get("min_score", 75)
        if score < min_score:
            violations.append({
                "rule": "Minimum Security Score",
                "message": f"Security score is {score}/100 (policy requires minimum {min_score})."
            })
        else:
            passed_checks.append({
                "rule": "Minimum Security Score",
                "message": f"Security score {score}/100 meets requirement ({min_score})."
            })

        # Check 4: Disallow Hardcoded Secrets
        if self.policy.get("disallow_secrets", True):
            secret_findings = [
                f for f in scan.findings
                if "SEC-SEC" in f.rule_id or f.rule_id in ("SEC-A02-001", "SEC-A02-006", "SEC-A02-007")
            ]
            if secret_findings:
                violations.append({
                    "rule": "Zero Hardcoded Secrets Policy",
                    "message": f"Detected {len(secret_findings)} exposed secrets/credentials in source files."
                })
            else:
                passed_checks.append({
                    "rule": "Zero Hardcoded Secrets Policy",
                    "message": "No plaintext secrets or cryptographic keys detected."
                })

        # Check 5: Disallow Unpinned Dependencies
        if self.policy.get("disallow_unpinned", False):
            unpinned = [f for f in scan.findings if f.rule_id == "SEC-A06-003"]
            if unpinned:
                violations.append({
                    "rule": "Pinned Dependencies Policy",
                    "message": f"Found {len(unpinned)} unpinned dependencies without strict version constraints."
                })
            else:
                passed_checks.append({
                    "rule": "Pinned Dependencies Policy",
                    "message": "All dependencies have pinned version locks."
                })

        # Determine Overall Status
        if len(violations) == 0:
            status = "PASSED"
            badge_class = "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
            exit_code = 0
            summary = "All security quality gate checks PASSED. Code meets production deployment standards."
        elif len(violations) == 1 and crit_count == 0:
            status = "WARNING"
            badge_class = "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
            exit_code = 0
            summary = f"Quality gate PASSED with 1 warning ({violations[0]['rule']})."
        else:
            status = "FAILED"
            badge_class = "bg-red-500/20 text-red-400 border-red-500/30"
            exit_code = 1
            summary = f"Security quality gate FAILED with {len(violations)} policy violation(s). Pipeline build should be blocked."

        return {
            "preset": self.preset_name,
            "policy_name": self.policy.get("name", self.preset_name.title()),
            "status": status,
            "exit_code": exit_code,
            "badge_class": badge_class,
            "summary": summary,
            "violations_count": len(violations),
            "violations": violations,
            "passed_count": len(passed_checks),
            "passed_checks": passed_checks,
            "thresholds": self.policy
        }
