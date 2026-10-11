"""Integration tests for OWASP Sentinel Web App and REST API."""

import pytest
import json
import os
from app import app, db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_index_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"OWASP Sentinel" in response.data
    assert b"Start Repository Security Scan" in response.data

def test_rules_catalog_page(client):
    response = client.get("/rules")
    assert response.status_code == 200
    assert b"OWASP Top 10 Rules Catalog" in response.data
    assert b"SEC-A01-001" in response.data
    assert b"SEC-A03-001" in response.data
    assert b"SEC-IAC-001" in response.data
    assert b"SEC-API-001" in response.data
    assert b"CIS-DOCKER-001" in response.data
    assert b"CWE-476-001" in response.data
    assert b"SLSA-CI-001" in response.data

def test_history_page(client):
    response = client.get("/history")
    assert response.status_code == 200
    assert b"Scan History" in response.data

def test_sample_scan_workflow(client):
    # 1. Trigger sample scan
    res = client.post("/api/scan", data={"scan_type": "sample"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "scan_id" in data
    scan_id = data["scan_id"]

    # 2. View scan details
    detail_res = client.get(f"/scan/{scan_id}")
    assert detail_res.status_code == 200
    assert b"OWASP Sample Vulnerable App" in detail_res.data
    assert b"Security Posture" in detail_res.data

    # 3. Verify JSON Export
    json_res = client.get(f"/api/scan/{scan_id}/export/json")
    assert json_res.status_code == 200
    exported_data = json.loads(json_res.data)
    assert exported_data["id"] == scan_id
    assert len(exported_data["findings"]) > 0

    # 4. Verify CSV Export
    csv_res = client.get(f"/api/scan/{scan_id}/export/csv")
    assert csv_res.status_code == 200
    assert b"Finding ID,Rule ID,Title" in csv_res.data

    # 5. Verify Markdown Export
    md_res = client.get(f"/api/scan/{scan_id}/export/md")
    assert md_res.status_code == 200
    assert b"# OWASP Security Scan Report" in md_res.data

    # 6. Verify Printable Report
    report_res = client.get(f"/scan/{scan_id}/report")
    assert report_res.status_code == 200
    assert b"Security Assessment Report" in report_res.data

    # 7. Update Finding Status
    finding_id = exported_data["findings"][0]["id"]
    status_res = client.post(
        f"/api/finding/{finding_id}/status",
        data=json.dumps({"status": "FALSE_POSITIVE", "notes": "Audited as test case"}),
        content_type="application/json"
    )
    assert status_res.status_code == 200
    assert status_res.get_json()["status"] == "FALSE_POSITIVE"

    # 8. Delete Scan
    del_res = client.delete(f"/api/scan/{scan_id}")
    assert del_res.status_code == 200
    assert del_res.get_json()["success"] is True

def test_invalid_git_url(client):
    res = client.post("/api/scan", data={"scan_type": "git", "repo_url": "ftp://bad-url"})
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert "Invalid Git URL" in data["error"]

def test_sarif_and_patch_exports(client):
    # Scan sample repo
    res = client.post("/api/scan", data={"scan_type": "sample"})
    scan_id = res.get_json()["scan_id"]

    # SARIF
    sarif_res = client.get(f"/api/scan/{scan_id}/export/sarif")
    assert sarif_res.status_code == 200
    sarif_json = json.loads(sarif_res.data)
    assert sarif_json["version"] == "2.1.0"
    assert sarif_json["runs"][0]["tool"]["driver"]["name"] == "OWASP Sentinel"

    # Patch
    patch_res = client.get(f"/api/scan/{scan_id}/export/patch")
    assert patch_res.status_code == 200
    assert b"# OWASP Sentinel Automated Security Patch" in patch_res.data

def test_custom_rules_flow(client):
    # 1. Regex test endpoint
    test_res = client.post(
        "/api/custom-rules/test",
        data=json.dumps({
            "pattern": r"AWS_SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",
            "code": "const AWS_SECRET_KEY = 'AKIA1234567890EXAMPLE';"
        }),
        content_type="application/json"
    )
    assert test_res.status_code == 200
    test_data = test_res.get_json()
    assert test_data["success"] is True
    assert test_data["matched"] is True

    # 2. Create custom rule
    rule_res = client.post(
        "/api/custom-rules",
        data=json.dumps({
            "id": "CUSTOM-TEST-001",
            "title": "Disallow Hardcoded Internal Key",
            "category": "A02:2021-Cryptographic Failures",
            "severity": "HIGH",
            "cwe": "CWE-798",
            "languages": ["js", "py"],
            "patterns": [r"internal_secret_[0-9]+"],
            "description": "Internal secret token pattern detected.",
            "remediation": "Load from environment variables."
        }),
        content_type="application/json"
    )
    assert rule_res.status_code == 200
    assert rule_res.get_json()["success"] is True

    # 3. View custom rules page
    cr_page = client.get("/custom-rules")
    assert cr_page.status_code == 200
    assert b"CUSTOM-TEST-001" in cr_page.data

    # 4. Delete custom rule
    del_res = client.delete("/api/custom-rules/CUSTOM-TEST-001")
    assert del_res.status_code == 200
    assert del_res.get_json()["success"] is True

def test_compare_and_cicd_views(client):
    # CI/CD view
    cicd_res = client.get("/cicd")
    assert cicd_res.status_code == 200
    assert b"CI/CD Integration Center" in cicd_res.data
    assert b"github/codeql-action/upload-sarif" in cicd_res.data

    # Compare view
    comp_res = client.get("/compare")
    assert comp_res.status_code == 200
    assert b"Scan Comparison" in comp_res.data


def test_sandbox_view_and_api(client):
    # Sandbox page
    sb_page = client.get("/sandbox")
    assert sb_page.status_code == 200
    assert b"Sentinel Live Sandbox" in sb_page.data

    # Sandbox scan API with vulnerable code snippet
    payload = {
        "language": "py",
        "code": "import os\nos.system('ping ' + host)\n"
    }
    scan_res = client.post(
        "/api/sandbox/scan",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert scan_res.status_code == 200
    res_data = scan_res.get_json()
    assert res_data["success"] is True
    assert len(res_data["findings"]) > 0
    assert res_data["findings"][0]["rule_id"] == "SEC-A03-002"


def test_compliance_and_sbom_endpoints(client):
    # Run sample scan
    scan_res = client.post("/api/scan", data={"scan_type": "sample"})
    scan_id = scan_res.get_json()["scan_id"]

    # 1. Compliance endpoint
    comp_res = client.get(f"/api/scan/{scan_id}/compliance")
    assert comp_res.status_code == 200
    comp_json = comp_res.get_json()
    assert comp_json["success"] is True
    assert "PCI-DSS" in comp_json["compliance"]
    assert "HIPAA" in comp_json["compliance"]
    assert "ISO-27001" in comp_json["compliance"]
    assert "CWE-TOP-25" in comp_json["compliance"]
    assert "CIS-BENCHMARKS" in comp_json["compliance"]
    assert "SLSA-SUPPLY-CHAIN" in comp_json["compliance"]
    assert "FOSS-GOVERNANCE" in comp_json["compliance"]

    # 2. CycloneDX SBOM export
    cdx_res = client.get(f"/api/scan/{scan_id}/export/cyclonedx")
    assert cdx_res.status_code == 200
    cdx_json = json.loads(cdx_res.data)
    assert cdx_json["bomFormat"] == "CycloneDX"
    assert cdx_json["specVersion"] == "1.5"

    # 3. SPDX SBOM export
    spdx_res = client.get(f"/api/scan/{scan_id}/export/spdx")
    assert spdx_res.status_code == 200
    spdx_json = json.loads(spdx_res.data)
    assert spdx_json["spdxVersion"] == "SPDX-2.3"

    # 4. SBOM JSON endpoint
    sbom_api = client.get(f"/api/scan/{scan_id}/sbom")
    assert sbom_api.status_code == 200
    assert sbom_api.get_json()["success"] is True

    # 5. Quality Gate API
    gate_res = client.get(f"/api/scan/{scan_id}/policy-gate?preset=strict")
    assert gate_res.status_code == 200
    gate_json = gate_res.get_json()
    assert gate_json["success"] is True
    assert gate_json["quality_gate"]["preset"] == "strict"
    assert gate_json["quality_gate"]["status"] == "FAILED"

    # 6. Analytics trends API
    trends_res = client.get("/api/analytics/trends")
    assert trends_res.status_code == 200
    assert trends_res.get_json()["success"] is True


def test_rescan_workflow(client):
    # 1. Trigger initial scan
    initial_res = client.post("/api/scan", data={"scan_type": "sample"})
    assert initial_res.status_code == 200
    initial_id = initial_res.get_json()["scan_id"]

    # 2. Rescan via API
    rescan_res = client.post(f"/api/scan/{initial_id}/rescan")
    assert rescan_res.status_code == 200
    rescan_data = rescan_res.get_json()
    assert rescan_data["success"] is True
    assert "scan_id" in rescan_data
    new_id = rescan_data["scan_id"]
    assert new_id != initial_id

    # 3. Verify new scan detail page renders
    detail_res = client.get(f"/scan/{new_id}")
    assert detail_res.status_code == 200
    assert b"OWASP Sample Vulnerable App" in detail_res.data
    assert b"Scanned Folders" in detail_res.data

    # 4. Verify folder counts persisted in database
    new_scan = db.get_scan(new_id)
    assert new_scan is not None
    assert isinstance(new_scan.folder_counts, dict)
    assert len(new_scan.folder_counts) > 0

    # 5. Non-existent scan rescan returns 404
    bad_res = client.post("/api/scan/invalid-uuid-12345/rescan")
    assert bad_res.status_code == 404
    assert bad_res.get_json()["success"] is False


def test_history_ui_and_search_elements(client):
    """Verify Scan History page renders KPIs, instant search, filters, and bulk operation elements."""
    # Ensure at least one scan exists
    client.post("/api/scan", data={"scan_type": "sample"})

    res = client.get("/history")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Header and KPI Cards
    assert "Scan History &amp; Audits" in html or "Scan History & Audits" in html
    assert "Total Audits" in html
    assert "Average Score" in html
    assert "Total Findings" in html
    assert "Clean / Passing" in html

    # Search & Filter Controls
    assert 'id="searchInput"' in html
    assert 'id="gradeFilter"' in html
    assert 'id="sourceFilter"' in html
    assert 'id="sortSelector"' in html
    assert 'id="pageSizeSelector"' in html
    assert 'id="masterCheckbox"' in html

    # Bulk Operations Toolbar & Modals
    assert 'id="bulkToolbar"' in html
    assert 'id="bulkCompareBtn"' in html
    assert 'id="bulkRescanBtn"' in html
    assert 'id="bulkExportBtn"' in html
    assert 'id="bulkDeleteBtn"' in html
    assert 'id="deleteConfirmModal"' in html
    assert 'id="bulkRescanModal"' in html


def test_bulk_delete_api(client):
    """Test bulk deletion of multiple scans."""
    # Create two scans
    res1 = client.post("/api/scan", data={"scan_type": "sample"})
    id1 = res1.get_json()["scan_id"]
    res2 = client.post("/api/scan", data={"scan_type": "sample"})
    id2 = res2.get_json()["scan_id"]

    assert db.get_scan(id1) is not None
    assert db.get_scan(id2) is not None

    # Error on empty scan_ids
    empty_res = client.post(
        "/api/scans/bulk-delete",
        data=json.dumps({"scan_ids": []}),
        content_type="application/json"
    )
    assert empty_res.status_code == 400
    assert empty_res.get_json()["success"] is False

    # Execute bulk delete
    bulk_del_res = client.post(
        "/api/scans/bulk-delete",
        data=json.dumps({"scan_ids": [id1, id2]}),
        content_type="application/json"
    )
    assert bulk_del_res.status_code == 200
    del_data = bulk_del_res.get_json()
    assert del_data["success"] is True
    assert del_data["deleted_count"] == 2

    # Verify deleted from DB
    assert db.get_scan(id1) is None
    assert db.get_scan(id2) is None


def test_bulk_export_api(client):
    """Test bulk consolidated JSON export for multiple scans."""
    # Create two scans
    res1 = client.post("/api/scan", data={"scan_type": "sample"})
    id1 = res1.get_json()["scan_id"]
    res2 = client.post("/api/scan", data={"scan_type": "sample"})
    id2 = res2.get_json()["scan_id"]

    # Error on missing or empty scan_ids
    empty_res = client.post(
        "/api/scans/bulk-export",
        data=json.dumps({"scan_ids": []}),
        content_type="application/json"
    )
    assert empty_res.status_code == 400

    # Non-existent scan ids return 404
    notfound_res = client.post(
        "/api/scans/bulk-export",
        data=json.dumps({"scan_ids": ["non-existent-id-1", "non-existent-id-2"]}),
        content_type="application/json"
    )
    assert notfound_res.status_code == 404

    # Valid bulk export
    export_res = client.post(
        "/api/scans/bulk-export",
        data=json.dumps({"scan_ids": [id1, id2]}),
        content_type="application/json"
    )
    assert export_res.status_code == 200
    assert "application/json" in export_res.content_type
    bundle = json.loads(export_res.data)

    assert bundle["export_type"] == "sentinel_bulk_scans_export"
    assert bundle["total_scans"] == 2
    assert len(bundle["scans"]) == 2
    exported_ids = [s["id"] for s in bundle["scans"]]
    assert id1 in exported_ids
    assert id2 in exported_ids


def test_bulk_rescan_api(client):
    """Test bulk rescan endpoint for multiple past audits."""
    # Create two initial scans
    res1 = client.post("/api/scan", data={"scan_type": "sample"})
    id1 = res1.get_json()["scan_id"]
    res2 = client.post("/api/scan", data={"scan_type": "sample"})
    id2 = res2.get_json()["scan_id"]

    # Trigger bulk rescan
    bulk_rescan_res = client.post(
        "/api/scans/bulk-rescan",
        data=json.dumps({"scan_ids": [id1, id2]}),
        content_type="application/json"
    )
    assert bulk_rescan_res.status_code == 200
    rescan_data = bulk_rescan_res.get_json()
    assert rescan_data["success"] is True
    assert rescan_data["rescanned_count"] == 2
    assert len(rescan_data["rescanned"]) == 2

    # Verify new scans were generated
    new_ids = [r["new_scan_id"] for r in rescan_data["rescanned"]]
    assert new_ids[0] != id1
    assert new_ids[1] != id2
    assert db.get_scan(new_ids[0]) is not None
    assert db.get_scan(new_ids[1]) is not None


def test_bulk_findings_status_api(client):
    """Test bulk triage status updates for multiple findings."""
    scan_res = client.post("/api/scan", data={"scan_type": "sample"})
    scan_id = scan_res.get_json()["scan_id"]
    scan = db.get_scan(scan_id)
    assert len(scan.findings) >= 2
    fid1 = scan.findings[0].id
    fid2 = scan.findings[1].id

    # Test bad request on empty list
    bad_res = client.post(
        "/api/findings/bulk-status",
        data=json.dumps({"finding_ids": [], "status": "RESOLVED"}),
        content_type="application/json"
    )
    assert bad_res.status_code == 400

    # Test bad request on invalid status
    bad_status_res = client.post(
        "/api/findings/bulk-status",
        data=json.dumps({"finding_ids": [fid1], "status": "INVALID_STATUS"}),
        content_type="application/json"
    )
    assert bad_status_res.status_code == 400

    # Test successful bulk update
    update_res = client.post(
        "/api/findings/bulk-status",
        data=json.dumps({"finding_ids": [fid1, fid2], "status": "RESOLVED"}),
        content_type="application/json"
    )
    assert update_res.status_code == 200
    res_data = update_res.get_json()
    assert res_data["success"] is True
    assert res_data["updated_count"] == 2
    assert res_data["status"] == "RESOLVED"

    # Reload scan and verify
    reloaded_scan = db.get_scan(scan_id)
    finding_map = {f.id: f.status for f in reloaded_scan.findings}
    assert finding_map[fid1] == "RESOLVED"
    assert finding_map[fid2] == "RESOLVED"


def test_ui_command_palette_and_charts(client):
    """Verify Command Palette, Dashboard Chart canvases, and Detail page bulk findings triage."""
    # 1. Dashboard UI checks
    dash_res = client.get("/")
    assert dash_res.status_code == 200
    dash_html = dash_res.data.decode("utf-8")

    # Command palette
    assert 'id="commandPaletteModal"' in dash_html
    assert 'id="commandPaletteInput"' in dash_html
    assert 'id="mobileMenu"' in dash_html

    # Analytics charts
    assert 'id="severityChart"' in dash_html
    assert 'id="categoryChart"' in dash_html
    assert 'id="trendChart"' in dash_html

    # Terminal scanning console
    assert 'id="scan-progress-overlay"' in dash_html
    assert 'id="scanTerminalLogs"' in dash_html

    # 2. Scan Detail UI checks
    scan_res = client.post("/api/scan", data={"scan_type": "sample"})
    scan_id = scan_res.get_json()["scan_id"]

    detail_res = client.get(f"/scan/{scan_id}")
    assert detail_res.status_code == 200
    detail_html = detail_res.data.decode("utf-8")

    assert 'id="bulkFindingsToolbar"' in detail_html
    assert 'id="selectAllFindingsCb"' in detail_html
    assert 'id="toggleDensityBtn"' in detail_html
    assert 'class="finding-cb' in detail_html





