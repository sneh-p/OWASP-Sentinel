"""SQLite database operations for OWASP Sentinel."""

import sqlite3
import json
import os
from typing import List, Optional, Dict, Any
from .models import ScanResult, Finding, Severity, OWASPCategory, Rule


class Database:
    def __init__(self, db_path: str = "data/sentinel.db"):
        self.db_path = db_path
        self._mem_conn = None
        if db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
        else:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        if self._mem_conn:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    repo_name TEXT NOT NULL,
                    repo_path TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    duration_seconds REAL DEFAULT 0.0,
                    total_files INTEGER DEFAULT 0,
                    scanned_files INTEGER DEFAULT 0,
                    lines_of_code INTEGER DEFAULT 0,
                    score INTEGER DEFAULT 100,
                    grade TEXT DEFAULT 'A+',
                    status TEXT DEFAULT 'completed',
                    error_message TEXT,
                    counts_by_severity TEXT,
                    counts_by_category TEXT,
                    source_url TEXT DEFAULT '',
                    branch TEXT DEFAULT '',
                    subfolder TEXT DEFAULT '',
                    folder_counts TEXT DEFAULT '{}'
                )
            """)

            # Ensure columns exist if table was already created in an earlier migration
            for col, col_def in [
                ("source_url", "TEXT DEFAULT ''"),
                ("branch", "TEXT DEFAULT ''"),
                ("subfolder", "TEXT DEFAULT ''"),
                ("folder_counts", "TEXT DEFAULT '{}'")
            ]:
                try:
                    cursor.execute(f"ALTER TABLE scans ADD COLUMN {col} {col_def}")
                except Exception:
                    pass

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_number INTEGER DEFAULT 1,
                    column_number INTEGER DEFAULT 0,
                    matched_line TEXT,
                    code_snippet TEXT,
                    description TEXT,
                    remediation TEXT,
                    status TEXT DEFAULT 'OPEN',
                    notes TEXT DEFAULT '',
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_category ON findings (category)")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_rules (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    languages TEXT NOT NULL,
                    patterns TEXT NOT NULL,
                    description TEXT,
                    remediation TEXT,
                    remediation_code TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def save_scan(self, scan: ScanResult) -> str:
        scan.calculate_metrics()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO scans (
                    id, repo_name, repo_path, source_type, created_at,
                    duration_seconds, total_files, scanned_files, lines_of_code,
                    score, grade, status, error_message,
                    counts_by_severity, counts_by_category,
                    source_url, branch, subfolder, folder_counts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.id,
                scan.repo_name,
                scan.repo_path,
                scan.source_type,
                scan.created_at,
                scan.duration_seconds,
                scan.total_files,
                scan.scanned_files,
                scan.lines_of_code,
                scan.score,
                scan.grade,
                scan.status,
                scan.error_message,
                json.dumps(scan.counts_by_severity),
                json.dumps(scan.counts_by_category),
                getattr(scan, "source_url", ""),
                getattr(scan, "branch", ""),
                getattr(scan, "subfolder", ""),
                json.dumps(getattr(scan, "folder_counts", {}))
            ))

            # Insert findings
            cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan.id,))
            for f in scan.findings:
                cursor.execute("""
                    INSERT INTO findings (
                        id, scan_id, rule_id, title, category, severity,
                        cwe, file_path, line_number, column_number,
                        matched_line, code_snippet, description, remediation,
                        status, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.id,
                    scan.id,
                    f.rule_id,
                    f.title,
                    f.category,
                    f.severity,
                    f.cwe,
                    f.file_path,
                    f.line_number,
                    f.column_number,
                    f.matched_line,
                    f.code_snippet,
                    f.description,
                    f.remediation,
                    f.status,
                    f.notes
                ))
            conn.commit()
        return scan.id

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None

            cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY line_number ASC", (scan_id,))
            finding_rows = cursor.fetchall()

            findings = []
            for fr in finding_rows:
                findings.append(Finding(
                    id=fr["id"],
                    scan_id=fr["scan_id"],
                    rule_id=fr["rule_id"],
                    title=fr["title"],
                    category=fr["category"],
                    severity=fr["severity"],
                    cwe=fr["cwe"],
                    file_path=fr["file_path"],
                    line_number=fr["line_number"],
                    column_number=fr["column_number"],
                    matched_line=fr["matched_line"] or "",
                    code_snippet=fr["code_snippet"] or "",
                    description=fr["description"] or "",
                    remediation=fr["remediation"] or "",
                    status=fr["status"] or "OPEN",
                    notes=fr["notes"] or ""
                ))

            row_keys = row.keys() if hasattr(row, "keys") else []
            source_url = row["source_url"] if "source_url" in row_keys else ""
            branch = row["branch"] if "branch" in row_keys else ""
            subfolder = row["subfolder"] if "subfolder" in row_keys else ""
            raw_fc = row["folder_counts"] if "folder_counts" in row_keys else "{}"
            folder_counts = json.loads(raw_fc) if raw_fc else {}

            scan = ScanResult(
                id=row["id"],
                repo_name=row["repo_name"],
                repo_path=row["repo_path"],
                source_type=row["source_type"],
                created_at=row["created_at"],
                duration_seconds=row["duration_seconds"],
                total_files=row["total_files"],
                scanned_files=row["scanned_files"],
                lines_of_code=row["lines_of_code"],
                score=row["score"],
                grade=row["grade"],
                status=row["status"],
                error_message=row["error_message"],
                findings=findings,
                counts_by_severity=json.loads(row["counts_by_severity"]) if row["counts_by_severity"] else {},
                counts_by_category=json.loads(row["counts_by_category"]) if row["counts_by_category"] else {},
                source_url=source_url or "",
                branch=branch or "",
                subfolder=subfolder or "",
                folder_counts=folder_counts
            )
            return scan

    def list_scans(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, count(f.id) as findings_count
                FROM scans s
                LEFT JOIN findings f ON s.id = f.scan_id
                GROUP BY s.id
                ORDER BY s.created_at DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                if item.get("counts_by_severity"):
                    item["counts_by_severity"] = json.loads(item["counts_by_severity"])
                if item.get("counts_by_category"):
                    item["counts_by_category"] = json.loads(item["counts_by_category"])
                results.append(item)
            return results

    def update_finding_status(self, finding_id: str, status: str, notes: str = "") -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE findings
                SET status = ?, notes = CASE WHEN ? != '' THEN ? ELSE notes END
                WHERE id = ?
            """, (status, notes, notes, finding_id))
            updated = cursor.rowcount > 0

            # Recalculate scan score
            cursor.execute("SELECT scan_id FROM findings WHERE id = ?", (finding_id,))
            row = cursor.fetchone()
            if row:
                scan_id = row["scan_id"]
                conn.commit()
                scan = self.get_scan(scan_id)
                if scan:
                    self.save_scan(scan)
            else:
                conn.commit()
            return updated

    def delete_scan(self, scan_id: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_dashboard_stats(self) -> Dict[str, Any]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total_scans FROM scans")
            total_scans = cursor.fetchone()["total_scans"]

            cursor.execute("SELECT COUNT(*) as total_findings FROM findings")
            total_findings = cursor.fetchone()["total_findings"]

            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM findings
                WHERE status != 'FALSE_POSITIVE'
                GROUP BY severity
            """)
            sev_rows = cursor.fetchall()
            sev_stats = {r["severity"]: r["count"] for r in sev_rows}

            cursor.execute("""
                SELECT category, COUNT(*) as count
                FROM findings
                WHERE status != 'FALSE_POSITIVE'
                GROUP BY category
                ORDER BY count DESC
                LIMIT 10
            """)
            cat_rows = cursor.fetchall()
            cat_stats = {r["category"].split(":")[0]: r["count"] for r in cat_rows}

            cursor.execute("""
                SELECT AVG(score) as avg_score
                FROM scans
                WHERE status = 'completed'
            """)
            avg_row = cursor.fetchone()
            avg_score = round(avg_row["avg_score"] or 100, 1)

            cursor.execute("""
                SELECT grade, COUNT(*) as count
                FROM scans
                WHERE status = 'completed'
                GROUP BY grade
            """)
            grade_rows = cursor.fetchall()
            grade_stats = {r["grade"]: r["count"] for r in grade_rows}

            cursor.execute("""
                SELECT COUNT(*) as count
                FROM scans
                WHERE status = 'completed' AND score >= 80
            """)
            pass_row = cursor.fetchone()
            passing_scans = pass_row["count"] if pass_row else 0

            return {
                "total_scans": total_scans,
                "total_findings": total_findings,
                "severity_stats": sev_stats,
                "category_stats": cat_stats,
                "average_score": avg_score,
                "grade_stats": grade_stats,
                "passing_scans": passing_scans
            }

    def save_custom_rule(self, rule_data: Dict[str, Any]) -> str:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            rule_id = rule_data.get("id", "").strip() or f"CUSTOM-{os.urandom(3).hex().upper()}"
            category_val = rule_data.get("category", "A01:2021-Broken Access Control")
            severity_val = rule_data.get("severity", "MEDIUM").upper()

            patterns = rule_data.get("patterns", [])
            if isinstance(patterns, list):
                patterns_json = json.dumps(patterns)
            else:
                patterns_json = json.dumps([str(patterns)])

            languages = rule_data.get("languages", ["*"])
            if isinstance(languages, list):
                languages_str = ",".join(languages)
            else:
                languages_str = str(languages)

            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()

            cursor.execute("""
                INSERT OR REPLACE INTO custom_rules (
                    id, title, category, severity, cwe, languages,
                    patterns, description, remediation, remediation_code,
                    is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_id,
                rule_data.get("title", "Custom Security Rule"),
                category_val,
                severity_val,
                rule_data.get("cwe", "CWE-Custom"),
                languages_str,
                patterns_json,
                rule_data.get("description", ""),
                rule_data.get("remediation", ""),
                rule_data.get("remediation_code", ""),
                1 if rule_data.get("is_active", True) else 0,
                now
            ))
            conn.commit()
            return rule_id

    def get_custom_rules(self, active_only: bool = True) -> List[Rule]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM custom_rules"
            if active_only:
                query += " WHERE is_active = 1"
            cursor.execute(query)
            rows = cursor.fetchall()
            rules = []
            for r in rows:
                try:
                    cat_obj = next((c for c in OWASPCategory if c.value == r["category"] or c.short_code == r["category"]), OWASPCategory.A01)
                    sev_obj = Severity[r["severity"].upper()]
                except Exception:
                    cat_obj = OWASPCategory.A01
                    sev_obj = Severity.MEDIUM

                langs = [l.strip() for l in r["languages"].split(",") if l.strip()]
                patterns = json.loads(r["patterns"]) if r["patterns"] else []

                rules.append(Rule(
                    id=r["id"],
                    title=r["title"],
                    category=cat_obj,
                    severity=sev_obj,
                    cwe=r["cwe"],
                    languages=langs,
                    description=r["description"] or "",
                    remediation=r["remediation"] or "",
                    patterns=patterns,
                    remediation_code=r["remediation_code"] or ""
                ))
            return rules

    def delete_custom_rule(self, rule_id: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
            conn.commit()
            return cursor.rowcount > 0

