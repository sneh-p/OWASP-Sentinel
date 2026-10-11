"""Regulatory and Industry Security Compliance Mapping for OWASP Sentinel.

Maps detected findings and rules to:
- PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
- HIPAA Security Rule (Health Insurance Portability and Accountability Act - 45 CFR Part 164)
- NIST SP 800-53 Rev 5 (Security and Privacy Controls for Federal Information Systems)
- SOC 2 Type II (Trust Services Criteria CC6, CC7, CC8)
"""

from typing import List, Dict, Any
from .models import Finding, Severity

# Framework Definitions & Control Catalogs
COMPLIANCE_CONTROLS = {
    "PCI-DSS": {
        "name": "PCI-DSS v4.0",
        "description": "Payment Card Industry Data Security Standard for cardholder data protection.",
        "icon": "credit-card",
        "controls": {
            "REQ-6.2.4": {
                "id": "REQ-6.2.4",
                "title": "Software Engineering Vulnerability Prevention (Injection, Overflow, Bad Auth)",
                "categories": ["A03", "A01", "A07", "API"],
                "cwes": ["CWE-89", "CWE-78", "CWE-79", "CWE-915", "CWE-287", "CWE-284"],
                "description": "Custom software is protected from common software vulnerabilities, including injection flaws, broken access controls, and authentication failures."
            },
            "REQ-3.4.1": {
                "id": "REQ-3.4.1",
                "title": "Protection of Sensitive Cardholder Data & Key Management",
                "categories": ["A02"],
                "cwes": ["CWE-798", "CWE-312", "CWE-327"],
                "description": "Never store plaintext credentials, cryptographic keys, or sensitive cardholder authentication data in source code or insecure storage."
            },
            "REQ-4.2.1": {
                "id": "REQ-4.2.1",
                "title": "Strong Cryptography for Data in Transit (TLS/SSL Enforcement)",
                "categories": ["A02"],
                "cwes": ["CWE-295"],
                "description": "Verify TLS certificates and use strong modern encryption protocols for all data transmission across open public networks."
            },
            "REQ-8.2.1": {
                "id": "REQ-8.2.1",
                "title": "User Identification and Strong Authentication Management",
                "categories": ["A07"],
                "cwes": ["CWE-287", "CWE-384", "CWE-1004", "CWE-614"],
                "description": "Enforce strong authentication mechanisms, secure cookies (HttpOnly, Secure), and prevent timing attacks or bypasses."
            },
            "REQ-6.3.2": {
                "id": "REQ-6.3.2",
                "title": "Software Bill of Materials & Third-Party Vulnerability Management",
                "categories": ["A06"],
                "cwes": ["CWE-1395", "CWE-1104"],
                "description": "Maintain an inventory of bespoke and third-party software components and remediate known vulnerabilities."
            },
            "REQ-10.2.1": {
                "id": "REQ-10.2.1",
                "title": "Audit Logging and Protection of Sensitive Log Data",
                "categories": ["A09"],
                "cwes": ["CWE-532", "CWE-778"],
                "description": "Log all administrative actions and security events while strictly prohibiting logging of passwords, tokens, or PII."
            }
        }
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "description": "45 CFR Part 164 - Safeguards for Electronic Protected Health Information (ePHI).",
        "icon": "heart-pulse",
        "controls": {
            "164.312(a)(1)": {
                "id": "164.312(a)(1)",
                "title": "Access Control (Technical Safeguards)",
                "categories": ["A01", "API"],
                "cwes": ["CWE-284", "CWE-285", "CWE-22", "CWE-250"],
                "description": "Implement technical policies and procedures allowing access only to persons or software programs granted access rights."
            },
            "164.312(c)(1)": {
                "id": "164.312(c)(1)",
                "title": "Data Integrity Controls",
                "categories": ["A08", "A03"],
                "cwes": ["CWE-502", "CWE-1321", "CWE-915"],
                "description": "Implement security measures to protect ePHI from improper alteration or destruction through deserialization, prototype pollution, or tampering."
            },
            "164.312(e)(1)": {
                "id": "164.312(e)(1)",
                "title": "Transmission Security & Encryption",
                "categories": ["A02"],
                "cwes": ["CWE-295", "CWE-312", "CWE-327"],
                "description": "Guard against unauthorized access to ePHI transmitted over electronic communications networks via strong TLS and encryption."
            },
            "164.312(b)": {
                "id": "164.312(b)",
                "title": "Audit Controls & Security Monitoring",
                "categories": ["A09"],
                "cwes": ["CWE-532", "CWE-778", "CWE-755"],
                "description": "Implement hardware, software, and procedural mechanisms that record and examine activity in information systems."
            }
        }
    },
    "NIST-800-53": {
        "name": "NIST SP 800-53 Rev 5",
        "description": "Security and Privacy Controls for Federal Information Systems and Organizations.",
        "icon": "shield-check",
        "controls": {
            "AC-3": {
                "id": "AC-3",
                "title": "Access Enforcement (Least Privilege & Boundary Defense)",
                "categories": ["A01", "IAC"],
                "cwes": ["CWE-284", "CWE-250", "CWE-732"],
                "description": "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies."
            },
            "SC-8": {
                "id": "SC-8",
                "title": "Transmission Confidentiality and Integrity",
                "categories": ["A02"],
                "cwes": ["CWE-295", "CWE-319"],
                "description": "Protect the confidentiality and integrity of transmitted information using verified cryptographic protocols."
            },
            "SC-13": {
                "id": "SC-13",
                "title": "Cryptographic Protection & Key Management",
                "categories": ["A02"],
                "cwes": ["CWE-798", "CWE-327", "CWE-312"],
                "description": "Employ validated cryptographic mechanisms for data protection and safeguard private keys from exposure."
            },
            "SI-10": {
                "id": "SI-10",
                "title": "Information Input Validation",
                "categories": ["A03", "A10"],
                "cwes": ["CWE-89", "CWE-78", "CWE-79", "CWE-611", "CWE-918", "CWE-1333"],
                "description": "Check the validity of information inputs to prevent injection attacks, SSRF, XML entity expansion, and ReDoS."
            },
            "SI-2": {
                "id": "SI-2",
                "title": "Flaw Remediation & Outdated Components",
                "categories": ["A06"],
                "cwes": ["CWE-1395", "CWE-1104"],
                "description": "Identify, report, and correct information system flaws and patch third-party libraries promptly."
            },
            "AU-2": {
                "id": "AU-2",
                "title": "Event Logging & Audit Generation",
                "categories": ["A09"],
                "cwes": ["CWE-532", "CWE-778"],
                "description": "Generate audit records containing information to establish what events occurred without logging sensitive credential secrets."
            }
        }
    },
    "SOC2": {
        "name": "SOC 2 Type II",
        "description": "AICPA Trust Services Criteria for Security, Confidentiality, and Availability.",
        "icon": "file-badge",
        "controls": {
            "CC6.1": {
                "id": "CC6.1",
                "title": "Logical Access Security & Authentication",
                "categories": ["A01", "A07", "IAC"],
                "cwes": ["CWE-284", "CWE-287", "CWE-250"],
                "description": "Controls provide reasonable assurance that logical access to data, software, and systems is protected against unauthorized access."
            },
            "CC6.6": {
                "id": "CC6.6",
                "title": "Boundary Protection & Infrastructure Defense",
                "categories": ["A05", "A10", "IAC"],
                "cwes": ["CWE-918", "CWE-732", "CWE-489"],
                "description": "Implement perimeter and cloud infrastructure protections against unauthorized access and unvalidated external requests."
            },
            "CC6.7": {
                "id": "CC6.7",
                "title": "Data Transmission & Encryption Safeguards",
                "categories": ["A02"],
                "cwes": ["CWE-295", "CWE-312", "CWE-798"],
                "description": "Transmit data securely using encryption and ensure private credentials are never hardcoded or leaked."
            },
            "CC7.1": {
                "id": "CC7.1",
                "title": "Vulnerability Detection & System Monitoring",
                "categories": ["A03", "A06", "A09"],
                "cwes": ["CWE-1395", "CWE-89", "CWE-78", "CWE-778"],
                "description": "Monitor systems and software components continuously for vulnerabilities, code injections, and anomalies."
            },
            "CC8.1": {
                "id": "CC8.1",
                "title": "Software Integrity & CI/CD Pipeline Controls",
                "categories": ["A08", "IAC", "SLSA"],
                "cwes": ["CWE-502", "CWE-78", "CWE-1357"],
                "description": "Authorize, design, develop, test, and implement changes to protect software integrity and secure build pipelines."
            }
        }
    },
    "ISO-27001": {
        "name": "ISO/IEC 27001:2022",
        "description": "International standard for Information Security Management Systems (ISMS) Annex A controls.",
        "icon": "globe-2",
        "controls": {
            "A.8.25": {
                "id": "A.8.25",
                "title": "Secure Development Life Cycle & Code Security",
                "categories": ["A01", "A03", "A07", "CWE-Top25"],
                "cwes": ["CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-287"],
                "description": "Rules for the secure development of software and systems shall be established and applied."
            },
            "A.8.28": {
                "id": "A.8.28",
                "title": "Secure Coding Principles & Vulnerability Defenses",
                "categories": ["A03", "A04", "System-Safety"],
                "cwes": ["CWE-476", "CWE-190", "CWE-362", "CWE-676"],
                "description": "Secure coding principles shall be applied to software development to defend against buffer errors, race conditions, and injection."
            },
            "A.8.8": {
                "id": "A.8.8",
                "title": "Management of Technical Vulnerabilities & Third-Party Dependencies",
                "categories": ["A06", "FOSS-Governance"],
                "cwes": ["CWE-1395", "CWE-1104"],
                "description": "Information about technical vulnerabilities of information systems being used shall be obtained, evaluated, and addressed."
            },
            "A.8.24": {
                "id": "A.8.24",
                "title": "Use of Cryptography & Key Protection",
                "categories": ["A02"],
                "cwes": ["CWE-798", "CWE-327", "CWE-295"],
                "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented."
            }
        }
    },
    "CWE-TOP-25": {
        "name": "MITRE CWE Top 25 (2023/2024)",
        "description": "The 25 Most Dangerous Software Weaknesses leading to severe real-world security exploits.",
        "icon": "shield-alert",
        "controls": {
            "CWE-INJECTION": {
                "id": "CWE-INJECTION",
                "title": "CWE #3, #5, #16: Query and Command Injections",
                "categories": ["A03"],
                "cwes": ["CWE-89", "CWE-78", "CWE-77"],
                "description": "Untrusted user inputs must be parameterized and sanitized to prevent SQL injection and OS command execution."
            },
            "CWE-MEMORY-SYSTEMS": {
                "id": "CWE-MEMORY-SYSTEMS",
                "title": "CWE #1, #4, #12, #14: Memory Safety & Pointer Handling",
                "categories": ["CWE-Top25", "System-Safety"],
                "cwes": ["CWE-787", "CWE-416", "CWE-476", "CWE-190", "CWE-119"],
                "description": "Defend against buffer overruns, NULL pointer dereferences, integer overflows, and use-after-free conditions."
            },
            "CWE-AUTH-ACCESS": {
                "id": "CWE-AUTH-ACCESS",
                "title": "CWE #8, #11, #13, #18, #25: Access Control & Permissions",
                "categories": ["A01", "A07", "System-Safety"],
                "cwes": ["CWE-22", "CWE-862", "CWE-287", "CWE-798", "CWE-276"],
                "description": "Enforce strict authentication, restrict file path traversal, eliminate hardcoded secrets, and prevent world-writable permissions."
            },
            "CWE-DESER-SSRF": {
                "id": "CWE-DESER-SSRF",
                "title": "CWE #15, #19: Deserialization and SSRF Weaknesses",
                "categories": ["A08", "A10"],
                "cwes": ["CWE-502", "CWE-918"],
                "description": "Protect against insecure deserialization leading to remote code execution, and restrict outbound server-side requests."
            }
        }
    },
    "CIS-BENCHMARKS": {
        "name": "CIS Cloud & Container Benchmarks",
        "description": "Center for Internet Security hardening baselines for Docker, Kubernetes, and Cloud IaC.",
        "icon": "box",
        "controls": {
            "CIS-CONTAINER-HARDEN": {
                "id": "CIS-CONTAINER-HARDEN",
                "title": "Container Hardening & Rootless Execution",
                "categories": ["CIS-Cloud-Container", "A05"],
                "cwes": ["CWE-250", "CWE-732", "CWE-1357"],
                "description": "Run containers as non-root, use immutable pinned tags, define healthchecks, and enforce read-only root filesystems."
            },
            "CIS-CLOUD-IAC": {
                "id": "CIS-CLOUD-IAC",
                "title": "Cloud Infrastructure & Network Boundary Hardening",
                "categories": ["CIS-Cloud-Container", "A01"],
                "cwes": ["CWE-284", "CWE-311", "CWE-732"],
                "description": "Eliminate 0.0.0.0/0 ingress on sensitive ports, enforce EBS/RDS encryption at rest, and prevent public bucket ACLs."
            }
        }
    },
    "SLSA-SUPPLY-CHAIN": {
        "name": "OpenSSF / SLSA Supply Chain",
        "description": "Supply-chain Levels for Software Artifacts (SLSA) and OpenSSF Secure Pipeline Guidelines.",
        "icon": "git-merge",
        "controls": {
            "SLSA-BUILD-L3": {
                "id": "SLSA-BUILD-L3",
                "title": "Immutable Action Digest Pinning & Build Hermeticity",
                "categories": ["SLSA-Supply-Chain"],
                "cwes": ["CWE-1357", "CWE-494"],
                "description": "Pin all third-party CI/CD actions to full 40-character commit SHAs and avoid unverified remote script downloads."
            },
            "SLSA-PIPELINE-ISOLATION": {
                "id": "SLSA-PIPELINE-ISOLATION",
                "title": "Least Privilege Pipeline Permissions & Secret Isolation",
                "categories": ["SLSA-Supply-Chain"],
                "cwes": ["CWE-250", "CWE-532", "CWE-284"],
                "description": "Restrict pipeline token permissions and eliminate script injection points in workflow pull request handlers."
            }
        }
    },
    "FOSS-GOVERNANCE": {
        "name": "FOSS Open Source Governance",
        "description": "Open Source Software License Compliance, Copyleft Risk Management, and Legal Due Diligence.",
        "icon": "scale",
        "controls": {
            "FOSS-COPYLEFT": {
                "id": "FOSS-COPYLEFT",
                "title": "Viral Copyleft Contamination Defense (GPL/AGPL)",
                "categories": ["FOSS-Governance"],
                "cwes": ["CWE-1395"],
                "description": "Detect strong copyleft licenses (GPL/AGPL/SSPL) that legally mandate releasing proprietary source code."
            },
            "FOSS-AUDIT": {
                "id": "FOSS-AUDIT",
                "title": "Software Bill of Materials (SBOM) & Third-Party Provenance",
                "categories": ["A06", "FOSS-Governance"],
                "cwes": ["CWE-1395", "CWE-1104"],
                "description": "Maintain a full component inventory with declared licenses and verified package provenance."
            }
        }
    }
}


def evaluate_compliance(findings: List[Finding]) -> Dict[str, Any]:
    """Evaluate repository findings against all major compliance frameworks."""
    framework_results: Dict[str, Any] = {}

    for fw_key, fw_spec in COMPLIANCE_CONTROLS.items():
        controls_status: Dict[str, Any] = {}
        total_controls = len(fw_spec["controls"])
        passed_controls = 0

        for ctrl_id, ctrl_meta in fw_spec["controls"].items():
            violating_findings: List[Dict[str, Any]] = []

            for f in findings:
                if f.status == "FALSE_POSITIVE":
                    continue

                cat_prefix = f.category.split(":")[0] if ":" in f.category else f.category[:3]
                rule_prefix = f.rule_id.split("-")[0] if "-" in f.rule_id else ""
                rule_mid = f.rule_id.split("-")[1] if "-" in f.rule_id and len(f.rule_id.split("-")) > 1 else ""

                # Check category, rule prefix, or CWE match
                cat_match = (
                    cat_prefix in ctrl_meta["categories"] or
                    rule_prefix in ctrl_meta["categories"] or
                    rule_mid in ctrl_meta["categories"] or
                    any(c in f.category for c in ctrl_meta["categories"]) or
                    any(fw in getattr(f, "frameworks", []) for fw in ctrl_meta.get("framework_tags", [])) or
                    ("IAC" in ctrl_meta["categories"] and ("IAC" in f.rule_id or "CIS" in f.rule_id)) or
                    ("API" in ctrl_meta["categories"] and "API" in f.rule_id)
                )
                cwe_match = f.cwe in ctrl_meta["cwes"]

                if cat_match or cwe_match:
                    violating_findings.append({
                        "finding_id": f.id,
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": f.severity,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "cwe": f.cwe
                    })

            is_compliant = len(violating_findings) == 0
            if is_compliant:
                passed_controls += 1

            controls_status[ctrl_id] = {
                "id": ctrl_meta["id"],
                "title": ctrl_meta["title"],
                "description": ctrl_meta["description"],
                "status": "COMPLIANT" if is_compliant else "NON_COMPLIANT",
                "violations_count": len(violating_findings),
                "violations": violating_findings
            }

        score_percent = round((passed_controls / total_controls) * 100) if total_controls > 0 else 100
        overall_status = "PASS" if score_percent >= 85 else ("WARNING" if score_percent >= 60 else "FAIL")

        framework_results[fw_key] = {
            "key": fw_key,
            "name": fw_spec["name"],
            "description": fw_spec["description"],
            "icon": fw_spec["icon"],
            "total_controls": total_controls,
            "passed_controls": passed_controls,
            "failed_controls": total_controls - passed_controls,
            "score_percentage": score_percent,
            "overall_status": overall_status,
            "controls": controls_status
        }

    return framework_results
