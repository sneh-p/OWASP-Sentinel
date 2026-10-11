# 🛡️ OWASP Sentinel

<div align="center">

**Unified Multi-Standard Static Application Security Testing (SAST), Policy-as-Code & Supply Chain Platform**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask 3.0](https://img.shields.io/badge/Flask-3.0-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-CSS-06B6D4.svg?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Tests](https://img.shields.io/badge/Tests-35%20Passed-emerald.svg?logo=pytest&logoColor=white)](#-automated-testing)
[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-OASIS%20v2.1.0-indigo.svg)](https://sarifweb.azurewebsites.net/)
[![CycloneDX v1.5](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5-purple.svg)](https://cyclonedx.org/)
[![SPDX v2.3](https://img.shields.io/badge/SBOM-SPDX%20v2.3-teal.svg)](https://spdx.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

*Audit codebases across **OWASP Top 10**, **MITRE CWE Top 25**, **CIS Cloud & Container Benchmarks**, **SLSA Supply Chain**, and **FOSS License Governance** with an interactive developer-first web dashboard, automated quality gates, and 1-click in-place code fixes.*

[Features](#-key-features) •
[Quick Start](#-quick-start) •
[Security Standards](#-multi-standard-security-coverage) •
[CLI Usage](#-command-line-interface-cli) •
[CI/CD Pipelines](#-cicd-pipeline-integration) •
[API Reference](#-rest-api-reference)

</div>

---

## 🌟 Overview

**OWASP Sentinel** is an enterprise-grade static analysis and application security platform designed to identify vulnerabilities early in the software development lifecycle. Sentinel inspects codebases locally without sending proprietary code off-premises, combining:

- **Deep AST (Abstract Syntax Tree) Traversal:** Language-aware syntax inspection for Python, JavaScript, and Go.
- **Polyglot Pattern Detection:** High-speed regular expression & semantic analysis across 79+ rules.
- **Infrastructure-as-Code (IaC) & Container Audits:** CIS benchmark checks for Dockerfiles, Kubernetes manifests, and Terraform files.
- **Software Supply Chain Security:** Known vulnerability CVE audits, automated SBOM generation (CycloneDX v1.5 & SPDX v2.3), and SLSA build hermeticity checks.
- **FOSS License Compliance:** Legal license governance detecting viral copyleft (GPL, AGPL, LGPL) vs permissive licenses.
- **Policy-as-Code Quality Gates:** Automated build gate enforcement with customizable severity thresholds.
- **1-Click Auto-Remediation:** In-place atomic patch engine and unified `.patch` export.

---

## 🚀 Key Features

### 🖥️ 1. Modern Interactive Web Experience
- **Universal Command Palette (`Ctrl+K` / `⌘K`):** Fast spotlight modal to jump between tools, navigate reports, or trigger scans via keyboard.
- **Interactive Telemetry Dashboards:** Live Chart.js visualizations for threat severity distributions, top threat categories, and historical health score trends.
- **Animated Scanner Terminal Console:** Simulated execution console showing real-time AST parsing, rule evaluation, and quality gate milestones.
- **Scan Comparison & Regression Engine (`/compare`):** Side-by-side delta engine detecting newly introduced flaws, resolved issues, and persistent vulnerabilities between branches or pull requests.
- **Responsive Mobile Navigation:** Full slide-down navigation drawer and responsive layouts for mobile and tablet screens.

### 📋 2. Scan History & Bulk Operations
- **Instant Client-Side Search:** Real-time search across repository names, Git branches, subfolders, and scan IDs.
- **Multi-Criteria Filtering & Sorting:** Filter by Grade (`A+` to `F`), Source (`Git`, `Upload`, `Sample`, `Local`), and sort by score, findings, or date.
- **Floating Sticky Bulk Action Toolbar:** Select multiple scans to execute:
  - **Bulk Export:** Consolidate selected audits into a single JSON archive.
  - **Bulk Rescan:** Re-evaluate repositories against the active ruleset with live progress logging.
  - **Bulk Delete:** Permanent batch deletion with confirmation modal.
  - **Compare (2 Selected):** Direct navigation to regression comparison when exactly 2 audits are selected.

### 🔍 3. Vulnerability Findings & Remediation Triage
- **Bulk Finding Status Triage:** Multi-select findings to batch-update status (`Open`, `Confirmed`, `False Positive`, `Resolved`).
- **View Density Controls:** Toggle between compact headline cards and detailed code context with a single click.
- **1-Click In-Place Auto-Fix:** Automatically patches identified vulnerabilities in the repository source code and marks the finding as `RESOLVED`.
- **Unified Patch Export:** Download multi-file `.patch` files compatible with `git apply`.

### 📦 4. Enterprise Standards & Compliance
- **Regulatory Compliance Matrix:** Real-time compliance evaluations against **PCI-DSS v4.0**, **HIPAA**, **NIST SP 800-53 Rev 5**, **SOC 2 Type II**, and **ISO/IEC 27001:2022**.
- **Software Bill of Materials (SBOM):** Native export in **CycloneDX v1.5 JSON** and **SPDX v2.3 JSON** formats.
- **OASIS SARIF v2.1.0:** Full compatibility with GitHub Code Scanning, GitLab SAST, and VS Code SARIF viewers.

### 🛠️ 5. Policy Studio & Playground
- **Interactive Code Sandbox (`/sandbox`):** Live code security sandbox evaluating code snippets across multiple languages in real-time.
- **Custom Security Rules Studio (`/custom-rules`):** Create, test, and register proprietary regex rules into the active scanning catalog with a live regex sandbox tester.
- **CI/CD Integration Center (`/cicd`):** Pre-built workflow configurations for GitHub Actions, GitLab CI, and pre-commit hooks.

---

## 🛡️ Multi-Standard Security Coverage

OWASP Sentinel integrates 79 built-in detection rules mapped across international standards:

| Framework | Coverage Scope | Flaws & Benchmarks Checked |
| :--- | :--- | :--- |
| **OWASP Top 10 (2021)** | Web Application Security | Broken Access Control (A01), Cryptographic Failures (A02), Injection (SQLi, Command, XSS) (A03), Insecure Design (A04), Security Misconfiguration (A05), Vulnerable Dependencies (A06), Auth Failures (A07), Integrity Failures (A08), Logging Failures (A09), SSRF (A10). |
| **MITRE CWE Top 25** | Most Dangerous Software Weaknesses | CWE-89 (SQLi), CWE-78 (OS Command), CWE-79 (XSS), CWE-22 (Path Traversal), CWE-476 (NULL Pointer), CWE-119 (Buffer Overflow), CWE-190 (Integer Overflow), CWE-416 (Use-After-Free), CWE-134 (Format String). |
| **CIS Benchmarks** | Cloud, Container & IaC | Docker root user, missing `HEALTHCHECK`, sensitive tokens in `ENV`, mutable tags; Kubernetes privileged pods, `hostNetwork`, `hostPID`, missing `securityContext`; Terraform unencrypted S3 buckets, unencrypted EBS volumes, open security groups (`0.0.0.0/0`). |
| **SLSA / OpenSSF** | Supply Chain Integrity | GitHub Actions unpinned commits (`@main`), `pull_request_target` code injection, missing top-level workflow permissions, unverified remote scripts (`curl \| bash`). |
| **FOSS Governance** | Open Source Licensing | Copyleft license contamination detection (GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-3.0) and permissive governance (MIT, Apache-2.0, BSD, ISC). |

---

## 💻 Quick Start

### Prerequisites
- Python 3.10 or higher
- Git (optional, for remote repository cloning)

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/your-username/owasp_sentinel.git
cd owasp_sentinel

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch the Web Interface

```bash
# Start Sentinel using the launcher script
./run.sh

# Or run directly via Python
python3 app.py
```

Open your browser to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## ⌨️ Command-Line Interface (CLI)

The `cli.py` utility allows running automated security scans in headless environments, build servers, and local terminal workflows.

```bash
# Scan a local folder
python3 cli.py scan /path/to/project

# Scan a remote Git repository
python3 cli.py scan https://github.com/OWASP/NodeGoat.git --branch master

# Scan and export to OASIS SARIF format
python3 cli.py scan ./my-project --sarif results.sarif

# Export CycloneDX v1.5 or SPDX v2.3 SBOM
python3 cli.py scan ./my-project --cyclonedx sbom.cyclonedx.json --spdx sbom.spdx.json

# Enforce CI/CD Quality Gate (fails build if threshold exceeded)
python3 cli.py scan ./my-project --gate-preset strict --fail-on-critical --min-score 85

# Compare two previous scans by ID for regressions
python3 cli.py compare <BASE_SCAN_ID> <TARGET_SCAN_ID>

# List all detection rules
python3 cli.py rules
```

### CLI Flag Reference

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `--branch` | `<name>` | Specific branch or tag to clone when scanning a Git URL. |
| `--json` | `<file>` | Output report to JSON file. |
| `--sarif` | `<file>` | Output report to OASIS SARIF v2.1.0 JSON file. |
| `--cyclonedx` | `<file>` | Output Software Bill of Materials (SBOM) in CycloneDX format. |
| `--spdx` | `<file>` | Output Software Bill of Materials (SBOM) in SPDX format. |
| `--save` | *flag* | Persist scan results to SQLite database. |
| `--diff` | `<scan_id>` | Compare scan results against an earlier baseline scan ID. |
| `--gate-preset` | `<preset>` | Quality gate preset: `strict`, `standard`, or `permissive`. |
| `--fail-on-critical`| *flag* | Exit with non-zero exit code if any Critical vulnerabilities are found. |
| `--min-score` | `<0-100>` | Minimum required security health score before failing the build. |
| `--max-critical` | `<N>` | Maximum permissible Critical findings before failing. |
| `--max-high` | `<N>` | Maximum permissible High findings before failing. |

---

## 🔄 CI/CD Pipeline Integration

### GitHub Actions Workflow

Create `.github/workflows/security-scan.yml` in your repository:

```yaml
name: "OWASP Sentinel Security Scan"

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]

jobs:
  sast-scan:
    name: "Static Analysis & Quality Gate"
    runs-on: ubuntu-latest

    steps:
      - name: "Checkout Code"
        uses: actions/checkout@v4

      - name: "Set up Python"
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: "Install OWASP Sentinel"
        run: |
          git clone https://github.com/your-username/owasp_sentinel.git /tmp/sentinel
          cd /tmp/sentinel
          pip install -r requirements.txt

      - name: "Run SAST Quality Gate"
        run: |
          python3 /tmp/sentinel/cli.py scan . \
            --sarif sentinel-results.sarif \
            --gate-preset standard \
            --fail-on-critical \
            --min-score 75

      - name: "Upload SARIF to GitHub Code Scanning"
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sentinel-results.sarif
```

---

## 🌐 REST API Reference

The web application exposes a comprehensive REST API for programmatic interaction:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/scan` | `POST` | Trigger repository scan (`scan_type`: `sample`, `git`, `upload`, `local`). |
| `/api/scan/<id>` | `DELETE` | Delete a scan and associated findings from history. |
| `/api/scan/<id>/rescan` | `POST` | Re-trigger scan using stored configuration parameters. |
| `/api/scans/bulk-delete` | `POST` | Batch delete scans by array of IDs `{ "scan_ids": [...] }`. |
| `/api/scans/bulk-export` | `POST` | Export multiple scans as a single consolidated JSON archive. |
| `/api/scans/bulk-rescan` | `POST` | Trigger batch rescanning of multiple repositories. |
| `/api/finding/<id>/status` | `POST` | Update single finding triage status (`OPEN`, `CONFIRMED`, `FALSE_POSITIVE`, `RESOLVED`). |
| `/api/findings/bulk-status`| `POST` | Batch update findings triage status `{ "finding_ids": [...], "status": "..." }`. |
| `/api/scan/<id>/apply-fix/<fid>` | `POST` | Apply atomic 1-click in-place code patch for a finding. |
| `/api/scan/<id>/export/sarif` | `GET` | Export scan findings in OASIS SARIF v2.1.0 format. |
| `/api/scan/<id>/export/cyclonedx` | `GET` | Export CycloneDX v1.5 JSON SBOM. |
| `/api/scan/<id>/export/spdx` | `GET` | Export SPDX v2.3 JSON SBOM. |
| `/api/scan/<id>/export/patch` | `GET` | Export multi-file unified git remediation `.patch`. |
| `/api/scan/<id>/compliance` | `GET` | Retrieve regulatory compliance evaluation (PCI-DSS, HIPAA, NIST, SOC 2). |
| `/api/scan/<id>/policy-gate` | `GET` | Evaluate scan against policy-as-code gate preset (`?preset=strict`). |
| `/api/custom-rules` | `GET`, `POST`| List or register custom regex security rules. |
| `/api/custom-rules/test` | `POST` | Test regular expression pattern sandbox against code snippet. |
| `/api/sandbox/scan` | `POST` | Execute live multi-language code security snippet evaluation. |
| `/api/analytics/trends` | `GET` | Historical security score trajectory and metrics. |

---

## 📁 Repository Structure

```
owasp_sentinel/
├── app.py                         # Flask Web Application & REST API
├── cli.py                         # Command-Line Interface & CI/CD Enforcer
├── run.sh                         # 1-Click Launch Script
├── requirements.txt               # Python Dependencies
├── data/
│   └── sentinel.db                # SQLite Persistent Database
├── scanner/                       # Core SAST Engine
│   ├── engine.py                  # Scanner Orchestrator, Walkers & Parsers
│   ├── models.py                  # Data Models (Rule, Finding, ScanResult)
│   ├── database.py                # Database Operations & Telemetry
│   ├── cwe_registry.py            # MITRE CWE Top 25 Mappings & Weakness Hierarchy
│   ├── license_checker.py         # FOSS Copyleft & Permissive License Auditor
│   ├── compliance_mapper.py       # Regulatory Compliance Matrix (PCI-DSS, HIPAA, NIST, SOC 2)
│   ├── sbom_generator.py          # CycloneDX v1.5 & SPDX v2.3 SBOM Generators
│   ├── policy_engine.py           # Policy-as-Code Quality Gate Engine
│   ├── diff_engine.py             # Scan Comparison & Regression Delta Engine
│   ├── patch_generator.py         # Unified Diff Generator & 1-Click Patch Applier
│   ├── sarif_exporter.py          # OASIS SARIF v2.1.0 Report Generator
│   ├── dependency_checker.py      # Dependency Vulnerability (CVE) Matcher
│   ├── repo_manager.py            # Git Clone & Safe Archive Extraction
│   ├── ast_analyzers/
│   │   └── python_ast.py          # Python AST Taint Analysis Visitor
│   └── rules/                     # 79 Built-in Static Analysis Rules
│       ├── catalog.py             # Central Rule Catalog & Registry
│       ├── a01_broken_access.py   # OWASP A01: Broken Access Control
│       ├── a02_crypto_failures.py # OWASP A02: Cryptographic Failures
│       ├── a03_injection.py       # OWASP A03: Injection Flaws
│       ├── a04_insecure_design.py # OWASP A04: Insecure Design
│       ├── a05_misconfiguration.py# OWASP A05: Security Misconfiguration
│       ├── a06_vulnerable_components.py # OWASP A06: Vulnerable Components
│       ├── a07_auth_failures.py   # OWASP A07: Authentication Failures
│       ├── a08_integrity_failures.py # OWASP A08: Software & Data Integrity
│       ├── a09_logging_failures.py# OWASP A09: Logging & Monitoring Failures
│       ├── a10_ssrf.py            # OWASP A10: Server-Side Request Forgery
│       ├── cis_container_rules.py # CIS Docker & Kubernetes Benchmarks
│       ├── cwe_core_rules.py      # CWE Top 25 Memory & Systems Safety Rules
│       ├── cicd_supply_chain_rules.py # SLSA Supply Chain & CI/CD Rules
│       ├── iac_rules.py           # Infrastructure-as-Code (Terraform / K8s) Rules
│       └── api_security.py        # REST API & GraphQL Security Rules
├── sample_vulnerable_repo/        # Multi-Language Testbed with Verified Flaws
│   ├── app.py                     # Vulnerable Flask Code (SQLi, Auth, SSRF, Deserialization)
│   ├── server.js                  # Vulnerable Express Code (XSS, Command Injection)
│   ├── Dockerfile                 # CIS Benchmark Flaws (Root user, missing healthcheck)
│   ├── k8s.yaml                   # Kubernetes Privileged Pod Manifest
│   ├── main.tf                    # Terraform Insecure Cloud Infrastructure
│   ├── .github/workflows/ci.yml   # Supply Chain Flaws (Unpinned actions)
│   ├── requirements.txt           # Vulnerable Dependencies with Known CVEs
│   └── package.json               # Vulnerable NPM Packages with Known CVEs
├── templates/                     # Modern Tailwind CSS HTML Templates
│   ├── base.html                  # Layout, Header, Command Palette & Mobile Drawer
│   ├── index.html                 # Dashboard, Telemetry Charts & Animated Scanner Console
│   ├── scan_detail.html           # Scan Report, Bulk Findings Triage & 1-Click Fixes
│   ├── history.html               # Scan History, Instant Search & Bulk Operations Toolbar
│   ├── compare.html               # Scan Comparison & Regression Analysis
│   ├── rules.html                 # Multi-Standard Rules Catalog Browser
│   ├── custom_rules.html          # Policy Studio & Regex Pattern Sandbox
│   ├── sandbox.html               # Interactive Code Security Playground
│   ├── cicd.html                  # CI/CD Pipeline Integration Center
│   └── report_export.html         # Printable Executive Assessment Report
├── static/
│   ├── css/custom.css             # Glassmorphism Styles & Custom Animations
│   └── js/app.js                  # Chart.js Telemetry & Terminal Console Animations
└── tests/
    ├── test_scanner.py            # Core Engine & Analyzer Unit Tests
    └── test_app.py                # Web Routes, REST API & Bulk Operations Tests
```

---

## 🧪 Automated Testing

The test suite validates rule matching, AST analysis, SBOM export, SARIF formatting, quality gates, and bulk REST API operations.

```bash
# Run the complete test suite with coverage
PYTHONPATH=. .venv/bin/pytest tests/ -v
```

```
tests/test_app.py .................                                      [ 48%]
tests/test_scanner.py ..................                                 [100%]
============================== 35 passed in 1.25s ==============================
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
