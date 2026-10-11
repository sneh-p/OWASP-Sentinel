"""SARIF (Static Analysis Results Interchange Format) v2.1.0 Exporter for OWASP Sentinel."""

from typing import Dict, Any, List
from .models import ScanResult, Finding, Severity

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def severity_to_sarif_level(severity_str: str) -> str:
    """Map OWASP Sentinel severity to SARIF result level."""
    s = severity_str.upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    elif s == "MEDIUM":
        return "warning"
    else:
        return "note"


def generate_sarif_report(scan: ScanResult) -> Dict[str, Any]:
    """Convert ScanResult into an OASIS SARIF v2.1.0 compliant dictionary."""
    rules_dict: Dict[str, Dict[str, Any]] = {}

    results: List[Dict[str, Any]] = []

    for finding in scan.findings:
        if finding.status == "FALSE_POSITIVE":
            continue

        rule_id = finding.rule_id
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": finding.title.replace(" ", ""),
                "shortDescription": {
                    "text": finding.title
                },
                "fullDescription": {
                    "text": finding.description
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(finding.severity)
                },
                "help": {
                    "text": finding.remediation,
                    "markdown": f"**Remediation:**\n\n{finding.remediation}\n\n**OWASP Category:** {finding.category}\n**CWE:** {finding.cwe}"
                },
                "properties": {
                    "category": finding.category,
                    "cwe": finding.cwe,
                    "precision": "high",
                    "security-severity": "9.0" if finding.severity == "CRITICAL" else ("7.0" if finding.severity == "HIGH" else "4.0")
                }
            }

        result_item: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": severity_to_sarif_level(finding.severity),
            "message": {
                "text": f"{finding.title} ({finding.cwe})"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": max(1, finding.line_number),
                            "snippet": {
                                "text": finding.matched_line or finding.code_snippet
                            }
                        }
                    }
                }
            ]
        }
        results.append(result_item)

    sarif_data = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OWASP Sentinel",
                        "version": "2.0.0",
                        "informationUri": "https://owasp.org/Top10/",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": results
            }
        ]
    }

    return sarif_data
