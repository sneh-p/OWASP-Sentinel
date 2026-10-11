#!/usr/bin/env python3
"""OWASP Sentinel CLI - Scan repositories and enforce CI/CD security quality gates."""

import argparse
import sys
import os
import json
from scanner.engine import ScannerEngine
from scanner.database import Database
from scanner.repo_manager import clone_git_repo
from scanner.sarif_exporter import generate_sarif_report
from scanner.diff_engine import compare_scans

def main():
    parser = argparse.ArgumentParser(
        description="OWASP Sentinel - Static Application Security Testing (SAST) & CI/CD Enforcer"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or Git repository")
    scan_parser.add_argument("target", help="Path to directory or Git repository URL")
    scan_parser.add_argument("--branch", help="Git branch to clone (if target is a Git URL)")
    scan_parser.add_argument("--json", dest="json_out", help="Export results to JSON file")
    scan_parser.add_argument("--sarif", dest="sarif_out", help="Export results to OASIS SARIF v2.1.0 file")
    scan_parser.add_argument("--save", action="store_true", help="Save results to Sentinel database")
    scan_parser.add_argument("--diff", dest="diff_base_id", help="Compare against previous scan ID in database")

    # Quality Gate options for CI/CD pipelines
    scan_parser.add_argument("--gate-preset", choices=["strict", "standard", "permissive"], help="Evaluate against Policy-as-Code Quality Gate preset")
    scan_parser.add_argument("--fail-on-critical", action="store_true", help="Exit with error code 1 if any CRITICAL vulnerabilities are found")
    scan_parser.add_argument("--min-score", type=int, default=0, help="Minimum acceptable security score (0-100). Exits with code 1 if lower.")
    scan_parser.add_argument("--max-critical", type=int, default=None, help="Maximum allowed CRITICAL vulnerabilities before failing build.")
    scan_parser.add_argument("--max-high", type=int, default=None, help="Maximum allowed HIGH vulnerabilities before failing build.")
    scan_parser.add_argument("--cyclonedx", dest="cyclonedx_out", help="Export CycloneDX v1.5 JSON SBOM to file")
    scan_parser.add_argument("--spdx", dest="spdx_out", help="Export SPDX v2.3 JSON SBOM to file")

    # Compare command
    comp_parser = subparsers.add_parser("compare", help="Compare two scans by ID from database")
    comp_parser.add_argument("base_id", help="Base scan ID (e.g. main branch)")
    comp_parser.add_argument("target_id", help="Target scan ID (e.g. PR branch)")

    # List rules command
    subparsers.add_parser("rules", help="List all OWASP rules")

    args = parser.parse_args()

    if args.command == "rules":
        from scanner.rules.catalog import catalog
        rules = catalog.get_all_rules()
        print(f"\nOWASP Sentinel Detection Rules ({len(rules)} total):\n")
        print(f"{'ID':<14} | {'Category':<10} | {'Severity':<9} | {'CWE':<9} | Title")
        print("-" * 80)
        for r in rules:
            cat_short = r.category.short_code
            print(f"{r.id:<14} | {cat_short:<10} | {r.severity.value:<9} | {r.cwe:<9} | {r.title}")
        print()
        sys.exit(0)

    elif args.command == "compare":
        db = Database("data/sentinel.db")
        base = db.get_scan(args.base_id)
        target = db.get_scan(args.target_id)
        if not base or not target:
            print(f"[!] Error: One or both scan IDs not found in database.", file=sys.stderr)
            sys.exit(1)

        diff = compare_scans(base, target)
        print("\n" + "=" * 60)
        print(f"  OWASP SENTINEL SCAN COMPARISON")
        print("=" * 60)
        print(f"Base Scan:     {diff.base_repo_name} ({diff.base_scan_id[:8]}) - Grade: {diff.base_grade} ({diff.base_score}/100)")
        print(f"Target Scan:   {diff.target_repo_name} ({diff.target_scan_id[:8]}) - Grade: {diff.target_grade} ({diff.target_score}/100)")
        delta_sign = "+" if diff.score_delta > 0 else ""
        print(f"Score Delta:   {delta_sign}{diff.score_delta} points")
        print("-" * 60)
        print(f"New Issues Introduced:   {len(diff.new_findings)}")
        print(f"Resolved / Fixed Issues: {len(diff.fixed_findings)}")
        print(f"Persistent Issues:       {len(diff.persistent_findings)}")
        print("=" * 60)

        if diff.new_findings:
            print("\n[!] NEW VULNERABILITIES INTRODUCED:")
            for f in diff.new_findings:
                print(f"  - [{f.severity}] {f.title} ({f.file_path}:{f.line_number})")

        if diff.fixed_findings:
            print("\n[+] RESOLVED VULNERABILITIES:")
            for f in diff.fixed_findings:
                print(f"  - [{f.severity}] {f.title} ({f.file_path}:{f.line_number})")

        print()
        sys.exit(0)

    elif args.command == "scan":
        target = args.target
        is_git = target.startswith("http://") or target.startswith("https://") or target.startswith("git@")
        clean_up_dir = None

        if is_git:
            print(f"[*] Cloning repository from {target}...")
            success, path_or_err = clone_git_repo(target, branch=args.branch)
            if not success:
                print(f"[!] Error: {path_or_err}", file=sys.stderr)
                sys.exit(1)
            scan_path = path_or_err
            clean_up_dir = path_or_err
            repo_name = target.rstrip("/").split("/")[-1].replace(".git", "")
            source_type = "git"
        else:
            if not os.path.exists(target):
                print(f"[!] Directory not found: {target}", file=sys.stderr)
                sys.exit(1)
            scan_path = os.path.abspath(target)
            repo_name = os.path.basename(scan_path.rstrip("/")) or "local_repo"
            source_type = "local"

        print(f"[*] Scanning {scan_path} for OWASP Top 10 vulnerabilities...")
        engine = ScannerEngine()
        result = engine.scan_directory(scan_path, repo_name=repo_name, source_type=source_type)

        db = Database("data/sentinel.db")
        if args.save or args.diff_base_id:
            db.save_scan(result)
            print(f"[+] Scan saved to database (ID: {result.id})")

        print("\n" + "=" * 60)
        print(f"  OWASP SENTINEL SCAN REPORT: {result.repo_name}")
        print("=" * 60)
        print(f"Security Grade:       {result.grade} ({result.score}/100)")
        print(f"Files Scanned:        {result.scanned_files} ({result.lines_of_code} LOC)")
        print(f"Duration:             {result.duration_seconds}s")
        print(f"Total Findings:       {len(result.findings)}")
        print(f"  - Critical:         {result.counts_by_severity.get('CRITICAL', 0)}")
        print(f"  - High:             {result.counts_by_severity.get('HIGH', 0)}")
        print(f"  - Medium:           {result.counts_by_severity.get('MEDIUM', 0)}")
        print(f"  - Low:              {result.counts_by_severity.get('LOW', 0)}")
        print("-" * 60)

        if result.findings:
            print(f"\n{'Severity':<9} | {'Rule ID':<14} | {'Location':<30} | Title")
            print("-" * 80)
            for f in result.findings:
                loc = f"{f.file_path}:{f.line_number}"
                if len(loc) > 28:
                    loc = "..." + loc[-25:]
                print(f"{f.severity:<9} | {f.rule_id:<14} | {loc:<30} | {f.title}")

        if args.diff_base_id:
            base_scan = db.get_scan(args.diff_base_id)
            if base_scan:
                diff = compare_scans(base_scan, result)
                print("\n" + "-" * 60)
                print(f"  REGRESSION ANALYSIS (vs {args.diff_base_id[:8]})")
                print("-" * 60)
                delta_sign = "+" if diff.score_delta > 0 else ""
                print(f"Score Change: {delta_sign}{diff.score_delta} ({diff.base_score} -> {diff.target_score})")
                print(f"New Issues:   {len(diff.new_findings)}")
                print(f"Fixed Issues: {len(diff.fixed_findings)}")
                if diff.new_findings:
                    print("\n[!] Newly Introduced:")
                    for nf in diff.new_findings:
                        print(f"  * [{nf.severity}] {nf.title} ({nf.file_path}:{nf.line_number})")

        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as jf:
                json.dump(result.to_dict(), jf, indent=2)
            print(f"\n[+] Results exported to {args.json_out}")

        if args.sarif_out:
            sarif_data = generate_sarif_report(result)
            with open(args.sarif_out, "w", encoding="utf-8") as sf:
                json.dump(sarif_data, sf, indent=2)
            print(f"\n[+] SARIF report exported to {args.sarif_out}")

        if args.cyclonedx_out:
            from scanner.sbom_generator import generate_cyclonedx_sbom
            cdx_data = generate_cyclonedx_sbom(result, repo_path=scan_path)
            with open(args.cyclonedx_out, "w", encoding="utf-8") as cf:
                json.dump(cdx_data, cf, indent=2)
            print(f"\n[+] CycloneDX v1.5 JSON SBOM exported to {args.cyclonedx_out}")

        if args.spdx_out:
            from scanner.sbom_generator import generate_spdx_sbom
            spdx_data = generate_spdx_sbom(result, repo_path=scan_path)
            with open(args.spdx_out, "w", encoding="utf-8") as sf:
                json.dump(spdx_data, sf, indent=2)
            print(f"\n[+] SPDX v2.3 JSON SBOM exported to {args.spdx_out}")

        if clean_up_dir:
            import shutil
            shutil.rmtree(clean_up_dir, ignore_errors=True)

        # CI/CD Quality Gate evaluation
        print("\n" + "=" * 60)
        print("  CI/CD QUALITY GATE EVALUATION")
        print("=" * 60)

        if args.gate_preset:
            from scanner.policy_engine import QualityGateEngine
            q_engine = QualityGateEngine(preset_name=args.gate_preset)
            gate_eval = q_engine.evaluate(result)
            print(f"Policy Preset: {gate_eval['policy_name']} (Status: {gate_eval['status']})")
            print(f"Summary:       {gate_eval['summary']}")
            if gate_eval["violations"]:
                print("\nViolations:")
                for v in gate_eval["violations"]:
                    print(f"  [X] {v['rule']}: {v['message']}")
            print()
            sys.exit(gate_eval["exit_code"])

        gate_failed = False
        crit_count = result.counts_by_severity.get("CRITICAL", 0)
        high_count = result.counts_by_severity.get("HIGH", 0)

        if args.fail_on_critical and crit_count > 0:
            print(f"[FAIL] Quality Gate Failed: Found {crit_count} CRITICAL vulnerabilities (--fail-on-critical)")
            gate_failed = True

        if args.max_critical is not None and crit_count > args.max_critical:
            print(f"[FAIL] Quality Gate Failed: {crit_count} CRITICAL vulnerabilities exceeds max threshold of {args.max_critical}")
            gate_failed = True

        if args.max_high is not None and high_count > args.max_high:
            print(f"[FAIL] Quality Gate Failed: {high_count} HIGH vulnerabilities exceeds max threshold of {args.max_high}")
            gate_failed = True

        if args.min_score > 0 and result.score < args.min_score:
            print(f"[FAIL] Quality Gate Failed: Security score {result.score} is below minimum required score of {args.min_score}")
            gate_failed = True

        if not gate_failed:
            print("[PASS] All Quality Gate criteria passed successfully!")
            print()
            sys.exit(0)
        else:
            print("[EXIT] Build failed due to security policy violations.")
            print()
            sys.exit(1)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
