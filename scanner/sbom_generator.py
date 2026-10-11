"""Software Bill of Materials (SBOM) Generator for OWASP Sentinel.

Supports standard CycloneDX v1.5 JSON and SPDX v2.3 JSON formats.
Follows US Executive Order 14028 and NTIA Minimum Elements for SBOMs.
"""

import os
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from .models import ScanResult, Finding


def extract_repo_dependencies(repo_path: str, findings: List[Finding]) -> List[Dict[str, Any]]:
    """Discover and parse software components across Python and Node.js manifests."""
    components: List[Dict[str, Any]] = []
    seen = set()

    # 1. Parse requirements.txt (Python)
    for root, _, files in os.walk(repo_path):
        for fname in files:
            if fname == "requirements.txt" or fname.endswith(".requirements.txt"):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                    for idx, line in enumerate(lines, start=1):
                        cl = line.strip()
                        if not cl or cl.startswith("#"):
                            continue
                        m = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|<=|>=|~=)?\s*([0-9a-zA-Z\.\-]+)?", cl)
                        if m:
                            name = m.group(1).lower()
                            ver = m.group(2) or "unpinned"
                            key = f"pypi:{name}:{ver}"
                            if key not in seen:
                                seen.add(key)
                                # Correlate with any CVE findings on this component
                                matched_vulns = []
                                for finding in findings:
                                    if name in finding.title.lower() or name in finding.matched_line.lower():
                                        matched_vulns.append({
                                            "cve": finding.cwe if "CVE" in finding.cwe else finding.title.split("(")[-1].replace(")", "") if "(" in finding.title else "N/A",
                                            "severity": finding.severity,
                                            "title": finding.title,
                                            "rule_id": finding.rule_id
                                        })
                                components.append({
                                    "name": name,
                                    "version": ver,
                                    "ecosystem": "pypi",
                                    "purl": f"pkg:pypi/{name}@{ver}" if ver != "unpinned" else f"pkg:pypi/{name}",
                                    "manifest_file": os.path.relpath(fpath, repo_path),
                                    "manifest_line": idx,
                                    "vulnerabilities": matched_vulns
                                })
                except Exception:
                    pass

            # 2. Parse package.json (Node.js)
            elif fname == "package.json":
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        pkg_data = json.load(f)
                    all_deps = {}
                    if "dependencies" in pkg_data and isinstance(pkg_data["dependencies"], dict):
                        all_deps.update(pkg_data["dependencies"])
                    if "devDependencies" in pkg_data and isinstance(pkg_data["devDependencies"], dict):
                        all_deps.update(pkg_data["devDependencies"])

                    for name, ver_spec in all_deps.items():
                        clean_ver = re.sub(r"[\^~>=<]", "", str(ver_spec)).strip() or "unpinned"
                        key = f"npm:{name}:{clean_ver}"
                        if key not in seen:
                            seen.add(key)
                            matched_vulns = []
                            for finding in findings:
                                if name in finding.title.lower() or name in finding.matched_line.lower():
                                    matched_vulns.append({
                                        "cve": finding.title.split("(")[-1].replace(")", "") if "(" in finding.title else "N/A",
                                        "severity": finding.severity,
                                        "title": finding.title,
                                        "rule_id": finding.rule_id
                                    })
                            components.append({
                                "name": name,
                                "version": clean_ver,
                                "ecosystem": "npm",
                                "purl": f"pkg:npm/{name}@{clean_ver}",
                                "manifest_file": os.path.relpath(fpath, repo_path),
                                "manifest_line": 1,
                                "vulnerabilities": matched_vulns
                            })
                except Exception:
                    pass

    return components


def generate_cyclonedx_sbom(scan: ScanResult, repo_path: str = "") -> Dict[str, Any]:
    """Generate CycloneDX v1.5 JSON formatted Software Bill of Materials."""
    path_to_use = repo_path or scan.repo_path or os.path.abspath("sample_vulnerable_repo")
    deps = extract_repo_dependencies(path_to_use, scan.findings)

    cdx_components: List[Dict[str, Any]] = []
    cdx_vulnerabilities: List[Dict[str, Any]] = []

    for dep in deps:
        bom_ref = f"bom-ref-{dep['ecosystem']}-{dep['name']}-{dep['version']}"
        component_entry = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": dep["name"],
            "version": dep["version"],
            "purl": dep["purl"],
            "scope": "required",
            "properties": [
                {"name": "sentinel:ecosystem", "value": dep["ecosystem"]},
                {"name": "sentinel:manifest", "value": f"{dep['manifest_file']}:{dep['manifest_line']}"}
            ]
        }
        cdx_components.append(component_entry)

        for v in dep.get("vulnerabilities", []):
            vuln_id = v["cve"] if v["cve"] != "N/A" else f"SENTINEL-{v['rule_id']}"
            cdx_vulnerabilities.append({
                "id": vuln_id,
                "source": {
                    "name": "OWASP Sentinel SAST",
                    "url": "https://owasp.org/www-project-top-ten/"
                },
                "ratings": [
                    {
                        "severity": v["severity"].lower(),
                        "method": "other"
                    }
                ],
                "description": v["title"],
                "affects": [
                    {"ref": bom_ref}
                ]
            })

    sbom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "OWASP Sentinel",
                    "name": "OWASP Sentinel SAST Engine",
                    "version": "2.2.0"
                }
            ],
            "component": {
                "type": "application",
                "name": scan.repo_name,
                "version": "1.0.0"
            }
        },
        "components": cdx_components,
        "vulnerabilities": cdx_vulnerabilities
    }
    return sbom


def generate_spdx_sbom(scan: ScanResult, repo_path: str = "") -> Dict[str, Any]:
    """Generate SPDX v2.3 JSON formatted Software Bill of Materials."""
    path_to_use = repo_path or scan.repo_path or os.path.abspath("sample_vulnerable_repo")
    deps = extract_repo_dependencies(path_to_use, scan.findings)

    spdx_packages: List[Dict[str, Any]] = []

    # Root application package
    root_spdx_id = "SPDXRef-Application"
    spdx_packages.append({
        "name": scan.repo_name,
        "SPDXID": root_spdx_id,
        "versionInfo": "1.0.0",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": "Organization: Custom Enterprise",
        "primaryPackagePurpose": "APPLICATION"
    })

    relationships: List[Dict[str, Any]] = []

    for idx, dep in enumerate(deps, start=1):
        pkg_id = f"SPDXRef-Package-{idx}-{dep['name']}"
        spdx_packages.append({
            "name": dep["name"],
            "SPDXID": pkg_id,
            "versionInfo": dep["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": dep["purl"]
                }
            ]
        })
        relationships.append({
            "spdxElementId": root_spdx_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": pkg_id
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM-{scan.repo_name}",
        "documentNamespace": f"https://sentinel.local/spdx/{scan.id}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": [
                "Tool: OWASP Sentinel-2.2.0"
            ]
        },
        "packages": spdx_packages,
        "relationships": relationships
    }
