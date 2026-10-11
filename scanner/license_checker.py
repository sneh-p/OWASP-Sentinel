"""Open Source Software (FOSS) License Compliance and Legal Risk Analyzer.

Analyzes declared dependencies and project manifests to identify:
- Strong Copyleft (Viral) licenses: AGPL-3.0, GPL-2.0, GPL-3.0, SSPL
- Weak Copyleft licenses: LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0
- Permissive licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC
- Commercial restrictions and missing license declarations
"""

import json
import re
from typing import List, Dict, Any, Tuple
from .models import Finding, SecurityCategory, Severity

# License Risk Classifications
STRONG_COPYLEFT = {
    "GPL-2.0", "GPL-3.0", "GPL-2.0-ONLY", "GPL-3.0-ONLY", "GPL-2.0-OR-LATER",
    "GPL-3.0-OR-LATER", "AGPL-3.0", "AGPL-3.0-ONLY", "AGPL-1.0", "SSPL-1.0",
    "EUPL-1.2", "OSL-3.0"
}

WEAK_COPYLEFT = {
    "LGPL-2.1", "LGPL-3.0", "LGPL-2.0", "MPL-2.0", "MPL-1.1", "EPL-1.0", "EPL-2.0", "CDDL-1.0"
}

PERMISSIVE = {
    "MIT", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC", "UNLICENSE", "CC0-1.0", "ZLIB"
}

# Known library license registry for popular dependencies
KNOWN_PACKAGE_LICENSES: Dict[str, str] = {
    # Strong Copyleft
    "readline": "GPL-3.0",
    "mysqlclient": "GPL-2.0",
    "pygpl": "GPL-3.0",
    "agpl-auth": "AGPL-3.0",
    # Weak Copyleft
    "psycopg2": "LGPL-3.0",
    "zeromq": "LGPL-3.0",
    "pygments": "BSD-2-Clause",
    # Permissive
    "flask": "BSD-3-Clause",
    "requests": "Apache-2.0",
    "django": "BSD-3-Clause",
    "express": "MIT",
    "lodash": "MIT",
    "react": "MIT",
    "axios": "MIT",
    "pytest": "MIT",
    "sqlalchemy": "MIT",
    "numpy": "BSD-3-Clause",
    "cryptography": "Apache-2.0",
    "bcrypt": "Apache-2.0",
    "pydantic": "MIT",
    "fastapi": "MIT",
    "celery": "BSD-3-Clause",
    "redis": "MIT",
}


def classify_license(license_str: str) -> Tuple[str, str]:
    """Classify license string into risk category and normalized identifier."""
    if not license_str:
        return "UNKNOWN", "Unspecified License"
    norm = license_str.strip().upper()

    for lic in STRONG_COPYLEFT:
        if lic in norm or norm == lic:
            return "STRONG_COPYLEFT", lic

    for lic in WEAK_COPYLEFT:
        if lic in norm or norm == lic:
            return "WEAK_COPYLEFT", lic

    for lic in PERMISSIVE:
        if lic in norm or norm == lic:
            return "PERMISSIVE", lic

    return "CUSTOM_OR_OTHER", license_str


def scan_manifest_licenses(content: str, file_path: str) -> List[Finding]:
    """Inspect package manifests for copyleft contamination risks in commercial repos."""
    findings: List[Finding] = []
    lines = content.splitlines()

    # 1. Inspect package.json
    if file_path.endswith("package.json"):
        try:
            data = json.loads(content)
            # Check root project license
            project_license = data.get("license")
            if isinstance(project_license, str):
                risk_tier, lic_name = classify_license(project_license)
                if risk_tier == "STRONG_COPYLEFT":
                    findings.append(Finding(
                        rule_id="LIC-GPL-001",
                        title=f"Strong Copyleft License Declared in Project Manifest ({lic_name})",
                        category=SecurityCategory.FOSS_LICENSE.value,
                        severity=Severity.HIGH.value,
                        cwe="CWE-1395",
                        file_path=file_path,
                        line_number=1,
                        matched_line=f'"license": "{project_license}"',
                        code_snippet=f'>>> "license": "{project_license}"',
                        description=(
                            f"The project declares '{lic_name}', a strong copyleft license. "
                            "If this repository is part of a commercial product, incorporating strong copyleft "
                            "code requires publishing the entire proprietary source code under the same open source terms."
                        ),
                        remediation=(
                            "For commercial proprietary software, switch to a permissive license (MIT, Apache-2.0) "
                            "or obtain a commercial proprietary dual-license from copyright holders."
                        ),
                        frameworks=["FOSS Governance", "Supply Chain Security"]
                    ))

            # Inspect dependencies in package.json
            deps = {}
            if "dependencies" in data and isinstance(data["dependencies"], dict):
                deps.update(data["dependencies"])
            if "devDependencies" in data and isinstance(data["devDependencies"], dict):
                deps.update(data["devDependencies"])

            for dep_name, version in deps.items():
                clean_name = dep_name.lower().strip()
                known_lic = KNOWN_PACKAGE_LICENSES.get(clean_name)
                if known_lic and known_lic in STRONG_COPYLEFT:
                    # Find line in lines
                    line_no = 1
                    for idx, l in enumerate(lines):
                        if f'"{dep_name}"' in l:
                            line_no = idx + 1
                            break

                    findings.append(Finding(
                        rule_id="LIC-GPL-002",
                        title=f"Viral Copyleft Dependency '{dep_name}' ({known_lic}) Detected",
                        category=SecurityCategory.FOSS_LICENSE.value,
                        severity=Severity.HIGH.value,
                        cwe="CWE-1395",
                        file_path=file_path,
                        line_number=line_no,
                        matched_line=lines[line_no - 1].strip() if line_no <= len(lines) else dep_name,
                        code_snippet=f">>> {lines[line_no - 1].strip() if line_no <= len(lines) else dep_name}",
                        description=(
                            f"Dependency '{dep_name}' is licensed under {known_lic} (Strong Copyleft). "
                            "Linking or distributing copyleft libraries with proprietary software may legally mandate "
                            "open-sourcing the host application under GPL/AGPL."
                        ),
                        remediation=f"Replace '{dep_name}' with a permissively licensed alternative (MIT/Apache-2.0/BSD).",
                        frameworks=["FOSS Governance", "Supply Chain Security"]
                    ))
        except Exception:
            pass

    # 2. Inspect requirements.txt
    elif file_path.endswith("requirements.txt") or "requirements" in file_path:
        for idx, line in enumerate(lines):
            clean = line.split("#")[0].strip()
            if not clean:
                continue
            pkg_match = re.match(r"^([a-zA-Z0-9_\-\.]+)", clean)
            if pkg_match:
                pkg_name = pkg_match.group(1).lower()
                known_lic = KNOWN_PACKAGE_LICENSES.get(pkg_name)
                if known_lic and known_lic in STRONG_COPYLEFT:
                    findings.append(Finding(
                        rule_id="LIC-GPL-002",
                        title=f"Viral Copyleft Dependency '{pkg_name}' ({known_lic}) Detected",
                        category=SecurityCategory.FOSS_LICENSE.value,
                        severity=Severity.HIGH.value,
                        cwe="CWE-1395",
                        file_path=file_path,
                        line_number=idx + 1,
                        matched_line=line.strip(),
                        code_snippet=f">>> {line.strip()}",
                        description=(
                            f"Python package '{pkg_name}' is licensed under {known_lic} (Strong Copyleft). "
                            "Inclusion in a proprietary codebase introduces legal contamination risks requiring full source disclosure."
                        ),
                        remediation=f"Replace '{pkg_name}' with an equivalent permissive library (MIT, BSD, Apache-2.0).",
                        frameworks=["FOSS Governance", "Supply Chain Security"]
                    ))

    return findings
