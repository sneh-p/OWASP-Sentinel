"""OWASP Sentinel - Web Application and REST API."""

import os
import shutil
import tempfile
import csv
import io
import json
from datetime import datetime, timezone
from flask import (
    Flask, render_template, request, jsonify, redirect, url_for,
    send_file, Response, flash
)
from werkzeug.utils import secure_filename

from scanner.database import Database
from scanner.engine import ScannerEngine
from scanner.models import ScanResult, Finding, OWASPCategory, OWASP_METADATA, Severity, Rule
from scanner.rules.catalog import catalog
from scanner.repo_manager import clone_git_repo, extract_zip
from scanner.sarif_exporter import generate_sarif_report
from scanner.diff_engine import compare_scans
from scanner.patch_generator import generate_scan_patch, generate_finding_diff, apply_remediation_to_file
from scanner.compliance_mapper import evaluate_compliance
from scanner.sbom_generator import generate_cyclonedx_sbom, generate_spdx_sbom, extract_repo_dependencies
from scanner.policy_engine import QualityGateEngine, QUALITY_GATE_PRESETS

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = os.path.abspath("uploads")
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = Database("data/sentinel.db")
engine = ScannerEngine()


@app.context_processor
def inject_globals():
    return {
        "owasp_meta": OWASP_METADATA,
        "severities": [s.value for s in Severity],
        "now_year": datetime.now(timezone.utc).year
    }


@app.route("/")
def index():
    """Dashboard homepage with new scan launcher and recent scans."""
    stats = db.get_dashboard_stats()
    recent_scans = db.list_scans(limit=10)
    all_rules = catalog.get_all_rules()
    return render_template(
        "index.html",
        stats=stats,
        recent_scans=recent_scans,
        rules_count=len(all_rules)
    )


@app.route("/scan/<scan_id>")
def scan_detail(scan_id: str):
    """Detailed scan report page with charts, findings, code viewer, and remediation diffs."""
    scan = db.get_scan(scan_id)
    if not scan:
        flash("Scan result not found.", "error")
        return redirect(url_for("index"))

    # Generate suggested remediation diffs where available
    diff_map = {}
    for f in scan.findings:
        diff_str = generate_finding_diff(f)
        if diff_str:
            diff_map[f.id] = diff_str

    # Quality Gate evaluation (default: standard)
    gate_preset = request.args.get("gate", "standard")
    q_engine = QualityGateEngine(preset_name=gate_preset)
    gate_result = q_engine.evaluate(scan)

    # Regulatory compliance matrix
    compliance_data = evaluate_compliance(scan.findings)

    # Software Bill of Materials (SBOM) dependency components
    repo_path = scan.repo_path if (scan.repo_path and os.path.exists(scan.repo_path)) else os.path.abspath("sample_vulnerable_repo")
    components = extract_repo_dependencies(repo_path, scan.findings)

    return render_template(
        "scan_detail.html",
        scan=scan,
        findings=scan.findings,
        diff_map=diff_map,
        owasp_meta=OWASP_METADATA,
        gate_result=gate_result,
        gate_presets=QUALITY_GATE_PRESETS,
        active_gate=gate_preset,
        compliance_data=compliance_data,
        components=components
    )


@app.route("/history")
def history():
    """Scan history page with comparison metrics."""
    scans = db.list_scans(limit=500)
    stats = db.get_dashboard_stats()
    return render_template("history.html", scans=scans, stats=stats)


@app.route("/compare")
def compare_view():
    """Scan comparison and regression analysis page."""
    base_id = request.args.get("base")
    target_id = request.args.get("target")
    all_scans = db.list_scans(limit=50)

    comparison = None
    if base_id and target_id:
        base_scan = db.get_scan(base_id)
        target_scan = db.get_scan(target_id)
        if base_scan and target_scan:
            comparison = compare_scans(base_scan, target_scan)

    return render_template(
        "compare.html",
        all_scans=all_scans,
        comparison=comparison,
        owasp_meta=OWASP_METADATA
    )


@app.route("/rules")
def rules_catalog():
    """Interactive OWASP Top 10 rule catalog browser."""
    all_rules = catalog.get_all_rules()
    categories = [cat for cat in OWASPCategory]
    return render_template(
        "rules.html",
        rules=all_rules,
        categories=categories,
        owasp_meta=OWASP_METADATA
    )


@app.route("/custom-rules")
def custom_rules_view():
    """Policy-as-code custom security rule studio and sandbox."""
    custom_rules = db.get_custom_rules(active_only=False)
    return render_template(
        "custom_rules.html",
        custom_rules=custom_rules,
        owasp_meta=OWASP_METADATA
    )


@app.route("/api/custom-rules", methods=["GET", "POST"])
def api_custom_rules():
    """Manage custom rules."""
    if request.method == "POST":
        data = request.get_json() or {}
        if not data.get("title") or not data.get("patterns"):
            return jsonify({"success": False, "error": "Title and patterns are required."}), 400

        rule_id = db.save_custom_rule(data)
        # Register into active catalog
        custom_rule_objs = db.get_custom_rules(active_only=True)
        catalog.load_custom_rules(custom_rule_objs)
        return jsonify({"success": True, "rule_id": rule_id})

    rules = [r.to_dict() for r in db.get_custom_rules(active_only=False)]
    return jsonify({"success": True, "rules": rules})


@app.route("/api/custom-rules/<rule_id>", methods=["DELETE"])
def api_delete_custom_rule(rule_id: str):
    """Delete a custom rule."""
    deleted = db.delete_custom_rule(rule_id)
    if deleted:
        catalog.unregister_rule(rule_id)
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Rule not found"}), 404


@app.route("/api/custom-rules/test", methods=["POST"])
def api_test_custom_rule():
    """Live pattern sandbox tester evaluating regex against code snippet."""
    data = request.get_json() or {}
    pattern_str = data.get("pattern", "")
    code = data.get("code", "")

    if not pattern_str:
        return jsonify({"success": False, "error": "Regex pattern cannot be empty."}), 400

    import re
    try:
        compiled = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
    except re.error as e:
        return jsonify({"success": False, "error": f"Invalid regular expression: {str(e)}"}), 400

    matches = []
    lines = code.splitlines()
    for idx, line in enumerate(lines, start=1):
        for m in compiled.finditer(line):
            matches.append({
                "line": idx,
                "text": m.group(0),
                "start": m.start(),
                "end": m.end()
            })

    return jsonify({
        "success": True,
        "matched": len(matches) > 0,
        "matches": matches
    })


@app.route("/cicd")
def cicd_view():
    """CI/CD integration center with GitHub Actions, GitLab CI, and pre-commit hook configs."""
    return render_template("cicd.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Execute repository scan via Git URL, Archive Upload, Local Path, or Sample Repo."""
    scan_type = request.form.get("scan_type", "sample")
    temp_dir_to_clean = None

    source_url = ""
    branch_name = ""
    subfolder_path = ""

    try:
        if scan_type == "sample":
            target_path = os.path.abspath("sample_vulnerable_repo")
            repo_name = "OWASP Sample Vulnerable App"
            source_type = "sample"
            source_url = "sample"

        elif scan_type == "git":
            repo_url = request.form.get("repo_url", "").strip()
            branch = request.form.get("branch", "").strip() or None
            subfolder = request.form.get("subfolder", "").strip().strip("/")
            if not repo_url:
                return jsonify({"success": False, "error": "Git repository URL is required."}), 400

            success, path_or_err = clone_git_repo(repo_url, branch=branch)
            if not success:
                return jsonify({"success": False, "error": path_or_err}), 400

            temp_dir_to_clean = path_or_err
            target_path = os.path.join(path_or_err, subfolder) if subfolder else path_or_err
            if not os.path.exists(target_path):
                return jsonify({"success": False, "error": f"Specified subfolder '{subfolder}' does not exist in repository."}), 400

            repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
            source_type = "git"
            source_url = repo_url
            branch_name = branch or ""
            subfolder_path = subfolder or ""

        elif scan_type == "upload":
            if "archive_file" not in request.files:
                return jsonify({"success": False, "error": "No file uploaded."}), 400

            file = request.files["archive_file"]
            if not file.filename or not file.filename.lower().endswith(".zip"):
                return jsonify({"success": False, "error": "Only .zip files are supported."}), 400

            filename = secure_filename(file.filename)
            zip_save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(zip_save_path)

            extract_dir = tempfile.mkdtemp(prefix="sentinel_upload_")
            temp_dir_to_clean = extract_dir

            success, msg = extract_zip(zip_save_path, extract_dir)
            try:
                os.remove(zip_save_path)
            except Exception:
                pass

            if not success:
                return jsonify({"success": False, "error": msg}), 400

            target_path = extract_dir
            repo_name = filename.rsplit(".", 1)[0]
            source_type = "upload"
            source_url = filename

        elif scan_type == "local":
            local_path = request.form.get("local_path", "").strip()
            if not local_path or not os.path.isdir(local_path):
                return jsonify({"success": False, "error": f"Invalid local directory path: '{local_path}'"}), 400

            target_path = os.path.abspath(local_path)
            repo_name = os.path.basename(target_path.rstrip("/")) or "local_repo"
            source_type = "local"
            source_url = target_path

        else:
            return jsonify({"success": False, "error": f"Unknown scan type: {scan_type}"}), 400

        # Load active custom rules from database
        custom_rules = db.get_custom_rules(active_only=True)
        catalog.load_custom_rules(custom_rules)

        # Run scanner engine
        scan_result = engine.scan_directory(
            target_dir=target_path,
            repo_name=repo_name,
            source_type=source_type
        )
        scan_result.source_url = source_url
        scan_result.branch = branch_name
        scan_result.subfolder = subfolder_path

        # Save to database
        scan_id = db.save_scan(scan_result)

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "redirect_url": url_for("scan_detail", scan_id=scan_id),
            "findings_count": len(scan_result.findings),
            "score": scan_result.score,
            "grade": scan_result.grade
        })

    except Exception as e:
        return jsonify({"success": False, "error": f"Scan failed: {str(e)}"}), 500

    finally:
        if temp_dir_to_clean and os.path.exists(temp_dir_to_clean):
            shutil.rmtree(temp_dir_to_clean, ignore_errors=True)


@app.route("/api/finding/<finding_id>/status", methods=["POST"])
def update_finding(finding_id: str):
    """Update finding triage status (OPEN, CONFIRMED, FALSE_POSITIVE, RESOLVED)."""
    data = request.get_json() or {}
    new_status = data.get("status", "OPEN").upper()
    notes = data.get("notes", "")

    if new_status not in ["OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"]:
        return jsonify({"success": False, "error": "Invalid status value"}), 400

    updated = db.update_finding_status(finding_id, new_status, notes=notes)
    if updated:
        return jsonify({"success": True, "status": new_status})
    return jsonify({"success": False, "error": "Finding not found"}), 404


@app.route("/api/findings/bulk-status", methods=["POST"])
def api_bulk_update_findings():
    """Bulk update triage status for multiple findings."""
    data = request.get_json() or {}
    finding_ids = data.get("finding_ids", [])
    new_status = data.get("status", "OPEN").upper()
    notes = data.get("notes", "")

    if not isinstance(finding_ids, list) or not finding_ids:
        return jsonify({"success": False, "error": "No finding IDs provided."}), 400

    if new_status not in ["OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"]:
        return jsonify({"success": False, "error": "Invalid status value"}), 400

    updated_count = 0
    for fid in finding_ids:
        if db.update_finding_status(str(fid), new_status, notes=notes):
            updated_count += 1

    return jsonify({
        "success": True,
        "updated_count": updated_count,
        "status": new_status,
        "message": f"Successfully updated {updated_count} finding{'s' if updated_count != 1 else ''} to {new_status}."
    })


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str):
    """Delete a scan from history."""
    deleted = db.delete_scan(scan_id)
    if deleted:
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Scan not found"}), 404


def _execute_single_rescan(scan_id: str):
    """Internal helper to execute a rescan for a given scan ID."""
    old_scan = db.get_scan(scan_id)
    if not old_scan:
        return False, "Scan record not found.", None

    temp_dir_to_clean = None
    try:
        source_type = old_scan.source_type
        repo_name = old_scan.repo_name
        source_url = getattr(old_scan, "source_url", "")
        branch_name = getattr(old_scan, "branch", "")
        subfolder_path = getattr(old_scan, "subfolder", "")

        if source_type == "git":
            if not source_url:
                return False, "Original Git URL not found in scan record. Please launch a new scan.", None

            success, path_or_err = clone_git_repo(source_url, branch=branch_name or None)
            if not success:
                return False, f"Failed to clone repository: {path_or_err}", None

            temp_dir_to_clean = path_or_err
            target_path = os.path.join(path_or_err, subfolder_path) if subfolder_path else path_or_err
            if not os.path.exists(target_path):
                return False, f"Subfolder '{subfolder_path}' does not exist in repository.", None

        elif source_type == "sample":
            target_path = os.path.abspath("sample_vulnerable_repo")
            source_url = "sample"

        elif source_type == "local":
            cand_path = source_url or old_scan.repo_path
            if not cand_path or not os.path.isdir(cand_path):
                return False, f"Original local directory '{cand_path}' is no longer accessible on disk.", None
            target_path = os.path.abspath(cand_path)
            source_url = target_path

        elif source_type == "upload":
            cand_path = old_scan.repo_path
            if not cand_path or not os.path.isdir(cand_path):
                return False, "Uploaded archive temporary files have expired. Please upload the zip archive again to rescan.", None
            target_path = cand_path
            source_url = getattr(old_scan, "source_url", "") or old_scan.repo_name

        else:
            return False, f"Unsupported scan source type: {source_type}", None

        # Load active custom rules from database
        custom_rules = db.get_custom_rules(active_only=True)
        catalog.load_custom_rules(custom_rules)

        # Run scanner engine
        scan_result = engine.scan_directory(
            target_dir=target_path,
            repo_name=repo_name,
            source_type=source_type
        )
        scan_result.source_url = source_url
        scan_result.branch = branch_name
        scan_result.subfolder = subfolder_path

        # Save to database
        new_scan_id = db.save_scan(scan_result)
        return True, new_scan_id, scan_result

    except Exception as e:
        return False, str(e), None

    finally:
        if temp_dir_to_clean and os.path.exists(temp_dir_to_clean):
            shutil.rmtree(temp_dir_to_clean, ignore_errors=True)


@app.route("/api/scan/<scan_id>/rescan", methods=["POST"])
def rescan(scan_id: str):
    """Re-trigger a scan using the recorded configuration and parameters of a previous scan."""
    success, res, scan_result = _execute_single_rescan(scan_id)
    if not success:
        status_code = 404 if "not found" in res.lower() else 400
        return jsonify({"success": False, "error": res}), status_code

    new_scan_id = res
    return jsonify({
        "success": True,
        "scan_id": new_scan_id,
        "redirect_url": url_for("scan_detail", scan_id=new_scan_id),
        "findings_count": len(scan_result.findings),
        "score": scan_result.score,
        "grade": scan_result.grade,
        "message": f"Rescan completed successfully. Found {len(scan_result.findings)} vulnerabilities."
    })


@app.route("/api/scans/bulk-delete", methods=["POST"])
def api_bulk_delete():
    """Bulk delete multiple scans by ID."""
    data = request.get_json() or {}
    scan_ids = data.get("scan_ids", [])
    if not isinstance(scan_ids, list) or not scan_ids:
        return jsonify({"success": False, "error": "No scan IDs provided."}), 400

    deleted_count = 0
    for sid in scan_ids:
        if db.delete_scan(str(sid)):
            deleted_count += 1

    return jsonify({
        "success": True,
        "deleted_count": deleted_count,
        "message": f"Successfully deleted {deleted_count} audit{'s' if deleted_count != 1 else ''}."
    })


@app.route("/api/scans/bulk-export", methods=["POST"])
def api_bulk_export():
    """Export multiple scans as a single consolidated JSON archive."""
    data = request.get_json() or {}
    scan_ids = data.get("scan_ids", [])
    if not isinstance(scan_ids, list) or not scan_ids:
        return jsonify({"success": False, "error": "No scan IDs provided."}), 400

    scans_data = []
    for sid in scan_ids:
        scan = db.get_scan(str(sid))
        if scan:
            scans_data.append(scan.to_dict())

    if not scans_data:
        return jsonify({"success": False, "error": "None of the requested scans were found."}), 404

    bundle = {
        "export_type": "sentinel_bulk_scans_export",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_scans": len(scans_data),
        "scans": scans_data
    }
    return Response(
        json.dumps(bundle, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=sentinel-bulk-audit-export-{len(scans_data)}-scans.json"}
    )


@app.route("/api/scans/bulk-rescan", methods=["POST"])
def api_bulk_rescan():
    """Trigger rescans for multiple past audits in bulk."""
    data = request.get_json() or {}
    scan_ids = data.get("scan_ids", [])
    if not isinstance(scan_ids, list) or not scan_ids:
        return jsonify({"success": False, "error": "No scan IDs provided."}), 400

    results = []
    failures = []
    for sid in scan_ids:
        success, res, scan_result = _execute_single_rescan(str(sid))
        if success:
            results.append({
                "old_scan_id": sid,
                "new_scan_id": res,
                "repo_name": scan_result.repo_name,
                "score": scan_result.score,
                "grade": scan_result.grade,
                "findings_count": len(scan_result.findings)
            })
        else:
            failures.append({
                "scan_id": sid,
                "error": res
            })

    return jsonify({
        "success": len(results) > 0 or len(failures) == 0,
        "rescanned_count": len(results),
        "rescanned": results,
        "failed": failures
    })



@app.route("/api/scan/<scan_id>/export/json")
def export_json(scan_id: str):
    """Export scan results as JSON."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    data = scan.to_dict()
    response = Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=sentinel-scan-{scan_id[:8]}.json"}
    )
    return response


@app.route("/api/scan/<scan_id>/export/csv")
def export_csv(scan_id: str):
    """Export scan findings as CSV."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Finding ID", "Rule ID", "Title", "OWASP Category", "Severity",
        "CWE", "File Path", "Line Number", "Status", "Description", "Remediation"
    ])

    for f in scan.findings:
        writer.writerow([
            f.id, f.rule_id, f.title, f.category, f.severity,
            f.cwe, f.file_path, f.line_number, f.status, f.description, f.remediation
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=sentinel-findings-{scan_id[:8]}.csv"}
    )


@app.route("/api/scan/<scan_id>/export/md")
def export_markdown(scan_id: str):
    """Export scan results as a Markdown document."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    md_lines = [
        f"# OWASP Security Scan Report: {scan.repo_name}",
        "",
        f"- **Scan Date:** {scan.created_at}",
        f"- **Security Score:** {scan.score}/100 (Grade: {scan.grade})",
        f"- **Total Files Scanned:** {scan.scanned_files} ({scan.lines_of_code} LOC)",
        f"- **Duration:** {scan.duration_seconds}s",
        f"- **Total Findings:** {len(scan.findings)}",
        "",
        "## Severity Breakdown",
        "",
        f"- **Critical:** {scan.counts_by_severity.get('CRITICAL', 0)}",
        f"- **High:** {scan.counts_by_severity.get('HIGH', 0)}",
        f"- **Medium:** {scan.counts_by_severity.get('MEDIUM', 0)}",
        f"- **Low:** {scan.counts_by_severity.get('LOW', 0)}",
        f"- **Info:** {scan.counts_by_severity.get('INFO', 0)}",
        "",
        "## Detailed Findings",
        ""
    ]

    for idx, f in enumerate(scan.findings, start=1):
        md_lines.extend([
            f"### {idx}. [{f.severity}] {f.title} ({f.rule_id})",
            "",
            f"- **OWASP Category:** {f.category}",
            f"- **CWE:** {f.cwe}",
            f"- **Location:** `{f.file_path}:{f.line_number}`",
            f"- **Status:** {f.status}",
            "",
            f"**Description:** {f.description}",
            "",
            "```",
            f.code_snippet,
            "```",
            "",
            f"**Remediation:**",
            f.remediation,
            "",
            "---",
            ""
        ])

    return Response(
        "\n".join(md_lines),
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment;filename=sentinel-report-{scan_id[:8]}.md"}
    )


@app.route("/api/scan/<scan_id>/export/sarif")
def export_sarif(scan_id: str):
    """Export scan results in OASIS SARIF v2.1.0 JSON format for GitHub / GitLab Code Scanning."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    sarif_data = generate_sarif_report(scan)
    return Response(
        json.dumps(sarif_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=sentinel-scan-{scan_id[:8]}.sarif"}
    )


@app.route("/api/scan/<scan_id>/export/patch")
def export_patch(scan_id: str):
    """Export multi-file unified git patch (.patch) for auto-remediating findings."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    patch_content = generate_scan_patch(scan)
    return Response(
        patch_content,
        mimetype="text/x-diff",
        headers={"Content-Disposition": f"attachment;filename=sentinel-remediation-{scan_id[:8]}.patch"}
    )


@app.route("/scan/<scan_id>/report")
def printable_report(scan_id: str):
    """Standalone printable/exportable HTML executive security report."""
    scan = db.get_scan(scan_id)
    if not scan:
        flash("Scan not found", "error")
        return redirect(url_for("index"))

    return render_template(
        "report_export.html",
        scan=scan,
        findings=scan.findings,
        owasp_meta=OWASP_METADATA
    )


@app.route("/api/scan/<scan_id>/compliance")
def api_scan_compliance(scan_id: str):
    """Return regulatory compliance evaluation (PCI-DSS, HIPAA, NIST 800-53, SOC 2)."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    data = evaluate_compliance(scan.findings)
    return jsonify({"success": True, "scan_id": scan_id, "compliance": data})


@app.route("/api/scan/<scan_id>/export/cyclonedx")
def export_cyclonedx(scan_id: str):
    """Export Software Bill of Materials (SBOM) in standard CycloneDX v1.5 JSON format."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    repo_path = scan.repo_path if (scan.repo_path and os.path.exists(scan.repo_path)) else os.path.abspath("sample_vulnerable_repo")
    sbom_data = generate_cyclonedx_sbom(scan, repo_path=repo_path)
    return Response(
        json.dumps(sbom_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=sentinel-sbom-{scan_id[:8]}.cyclonedx.json"}
    )


@app.route("/api/scan/<scan_id>/export/spdx")
def export_spdx(scan_id: str):
    """Export Software Bill of Materials (SBOM) in standard SPDX v2.3 JSON format."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    repo_path = scan.repo_path if (scan.repo_path and os.path.exists(scan.repo_path)) else os.path.abspath("sample_vulnerable_repo")
    spdx_data = generate_spdx_sbom(scan, repo_path=repo_path)
    return Response(
        json.dumps(spdx_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=sentinel-sbom-{scan_id[:8]}.spdx.json"}
    )


@app.route("/api/scan/<scan_id>/sbom")
def api_scan_sbom(scan_id: str):
    """Return parsed dependency inventory and components."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    repo_path = scan.repo_path if (scan.repo_path and os.path.exists(scan.repo_path)) else os.path.abspath("sample_vulnerable_repo")
    components = extract_repo_dependencies(repo_path, scan.findings)
    return jsonify({"success": True, "scan_id": scan_id, "components": components})


@app.route("/api/scan/<scan_id>/policy-gate")
def api_scan_policy_gate(scan_id: str):
    """Evaluate scan against policy-as-code quality gate."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    preset = request.args.get("preset", "standard")
    q_engine = QualityGateEngine(preset_name=preset)
    result = q_engine.evaluate(scan)
    return jsonify({"success": True, "scan_id": scan_id, "quality_gate": result})


@app.route("/api/scan/<scan_id>/apply-fix/<finding_id>", methods=["POST"])
def api_apply_finding_fix(scan_id: str, finding_id: str):
    """Atomically apply the suggested remediation to the repository file and mark finding as RESOLVED."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan not found"}), 404

    target_finding = next((f for f in scan.findings if f.id == finding_id), None)
    if not target_finding:
        return jsonify({"success": False, "error": "Finding not found"}), 404

    repo_path = scan.repo_path if (scan.repo_path and os.path.exists(scan.repo_path)) else os.path.abspath("sample_vulnerable_repo")
    applied = apply_remediation_to_file(repo_path, target_finding)

    if applied:
        db.update_finding_status(finding_id, "RESOLVED", notes="Auto-remediated via OWASP Sentinel 1-Click Fix")
        return jsonify({
            "success": True,
            "finding_id": finding_id,
            "status": "RESOLVED",
            "message": f"Remediation successfully applied to {target_finding.file_path}"
        })
    else:
        return jsonify({
            "success": False,
            "error": "Automated patch pattern could not be applied automatically. Please apply manually."
        }), 400


@app.route("/sandbox")
def sandbox_view():
    """Interactive real-time code security playground."""
    return render_template("sandbox.html")


@app.route("/api/sandbox/scan", methods=["POST"])
def api_sandbox_scan():
    """Live code snippet SAST analysis without repo creation."""
    import time
    data = request.get_json() or {}
    code = data.get("code", "")
    lang = data.get("language", "py").lower()

    if not code.strip():
        return jsonify({"success": False, "error": "Code cannot be empty"}), 400

    ext_map = {
        "py": "snippet.py",
        "js": "snippet.js",
        "ts": "snippet.ts",
        "tf": "main.tf",
        "yaml": "k8s.yaml",
        "yml": "k8s.yaml",
        "dockerfile": "Dockerfile"
    }
    fname = ext_map.get(lang, "snippet.txt")

    tmp_dir = tempfile.mkdtemp(prefix="sentinel_sandbox_")
    tmp_file = os.path.join(tmp_dir, fname)

    t0 = time.time()
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(code)

        findings = engine.scan_file(tmp_file, tmp_dir)

        out_findings = []
        for f in findings:
            f_dict = f.to_dict()
            f_dict["diff"] = generate_finding_diff(f)
            out_findings.append(f_dict)

        duration_ms = round((time.time() - t0) * 1000, 1)

        return jsonify({
            "success": True,
            "duration_ms": duration_ms,
            "lines_of_code": len(code.splitlines()),
            "findings": out_findings
        })
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.route("/api/analytics/trends")
def api_analytics_trends():
    """Return historical vulnerability trends, scores, and mean time to remediate."""
    scans = db.list_scans(limit=30)
    history_points = []
    category_totals = {}
    for s in reversed(scans):
        history_points.append({
            "id": s["id"],
            "repo_name": s["repo_name"],
            "date": s["created_at"][:10],
            "score": s["score"],
            "grade": s["grade"],
            "findings_count": s["findings_count"]
        })

    return jsonify({
        "success": True,
        "scans_count": len(scans),
        "history": history_points
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
