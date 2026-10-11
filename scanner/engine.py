"""Core Static Application Security Testing (SAST) Scanner Engine."""

import os
import re
import time
from typing import List, Callable, Optional, Set
from .models import ScanResult, Finding, Severity, OWASPCategory
from .rules.catalog import catalog
from .ast_analyzers.python_ast import analyze_python_ast
from .dependency_checker import scan_requirements_txt, scan_package_json
from .entropy_scanner import scan_content_for_secrets
from .license_checker import scan_manifest_licenses
from .cwe_registry import get_cwe_top25_rank, resolve_frameworks

DEFAULT_EXCLUDED_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "__pycache__",
    ".venv", "venv", "env", ".tox", ".pytest_cache", ".mypy_cache",
    ".idea", ".vscode", "dist", "build", "target", "bin", "obj",
    "coverage", ".next", ".nuxt"
}

SCANNABLE_EXTENSIONS: Set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".go",
    ".rb", ".cs", ".c", ".cpp", ".sh", ".bash", ".json", ".yml",
    ".yaml", ".env", ".xml", ".html", ".conf", ".ini", ".txt",
    ".tf", ".hcl", ".dockerfile"
}

BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc", ".db", ".sqlite"
}


class ScannerEngine:
    def __init__(self, excluded_dirs: Optional[Set[str]] = None):
        self.excluded_dirs = excluded_dirs or DEFAULT_EXCLUDED_DIRS

    def _extract_snippet(self, lines: List[str], line_no: int, context: int = 3) -> str:
        start = max(0, line_no - 1 - context)
        end = min(len(lines), line_no + context)
        out = []
        for idx in range(start, end):
            prefix = ">>> " if idx == line_no - 1 else "    "
            line_str = lines[idx] if idx < len(lines) else ""
            out.append(f"{idx + 1:4d} | {prefix}{line_str}")
        return "\n".join(out)

    def scan_file(self, file_path: str, base_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        rel_path = os.path.relpath(file_path, base_dir)
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        if ext in BINARY_EXTENSIONS:
            return findings

        filename = os.path.basename(file_path).lower()
        lookup_ext = "dockerfile" if filename.startswith("dockerfile") else ext.lstrip(".")

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return findings

        lines = content.splitlines()

        # 1. Dependency & License Governance Scans
        if filename == "requirements.txt" or filename.endswith(".requirements.txt"):
            findings.extend(scan_requirements_txt(content, rel_path))
            findings.extend(scan_manifest_licenses(content, rel_path))
        elif filename == "package.json":
            findings.extend(scan_package_json(content, rel_path))
            findings.extend(scan_manifest_licenses(content, rel_path))

        # 2. Python AST Analysis
        if ext == ".py":
            ast_findings = analyze_python_ast(rel_path, content)
            findings.extend(ast_findings)

        # 3. Enterprise Secrets & Shannon Entropy Analysis
        secret_findings = scan_content_for_secrets(content, rel_path, lines)
        findings.extend(secret_findings)

        # 4. Rule Catalog Pattern Matching
        applicable_rules = catalog.get_rules_for_language(lookup_ext)

        for rule in applicable_rules:
            if not rule.patterns:
                continue

            for pattern_str in rule.patterns:
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                except re.error:
                    continue

                for match in compiled.finditer(content):
                    # Compute line number from character offset
                    char_offset = match.start()
                    line_no = content[:char_offset].count("\n") + 1
                    matched_text = match.group(0).splitlines()[0] if match.group(0) else ""

                    line_str = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                    # Suppress comment lines for non-credential rules
                    if (line_str.startswith("#") or line_str.startswith("//") or line_str.startswith("/*")) and rule.category != OWASPCategory.A02:
                        continue

                    # Deduplication check: if AST or another rule already caught this exact rule on this line
                    already_found = any(
                        f.rule_id == rule.id and abs(f.line_number - line_no) <= 2
                        for f in findings
                    )
                    if already_found:
                        continue

                    snippet = self._extract_snippet(lines, line_no)

                    finding = Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        category=rule.category.value if hasattr(rule.category, "value") else str(rule.category),
                        severity=rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity),
                        cwe=rule.cwe,
                        file_path=rel_path,
                        line_number=line_no,
                        matched_line=matched_text.strip(),
                        code_snippet=snippet,
                        description=rule.description,
                        remediation=rule.remediation + (
                            f"\n\nRecommended Fix:\n```\n{rule.remediation_code}\n```"
                            if rule.remediation_code else ""
                        ),
                        cwe_rank=rule.cwe_rank or get_cwe_top25_rank(rule.cwe),
                        frameworks=rule.frameworks or resolve_frameworks(rule.id, rule.category.value if hasattr(rule.category, "value") else str(rule.category), rule.cwe),
                    )
                    findings.append(finding)

        # Enrich any findings (from AST, dependencies, licenses, secrets)
        for f in findings:
            if not f.cwe_rank:
                f.cwe_rank = get_cwe_top25_rank(f.cwe)
            if not f.frameworks:
                f.frameworks = resolve_frameworks(f.rule_id, f.category, f.cwe)

        return findings

    def scan_directory(
        self,
        target_dir: str,
        repo_name: str = "",
        source_type: str = "local",
        progress_callback: Optional[Callable[[int, int, str, int], None]] = None
    ) -> ScanResult:
        start_time = time.time()
        target_dir = os.path.abspath(target_dir)

        if not repo_name:
            repo_name = os.path.basename(target_dir.rstrip("/")) or "scanned_repo"

        # Discover all scannable files
        file_list: List[str] = []
        folder_counts: Dict[str, int] = {}

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [
                d for d in dirs
                if d not in self.excluded_dirs and (not d.startswith(".") or d in (".github", ".gitlab", ".circleci", ".config"))
            ]
            for file in files:
                _, ext = os.path.splitext(file)
                ext = ext.lower()
                if ext in SCANNABLE_EXTENSIONS or file in ("Dockerfile", "Makefile", "Pipfile", ".env") or file.lower().startswith("dockerfile"):
                    full_p = os.path.join(root, file)
                    file_list.append(full_p)
                    rel_dir = os.path.relpath(root, target_dir)
                    folder_counts[rel_dir] = folder_counts.get(rel_dir, 0) + 1

        total_files = len(file_list)
        all_findings: List[Finding] = []
        total_loc = 0

        for idx, fpath in enumerate(file_list, start=1):
            try:
                # Count lines of code
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    total_loc += sum(1 for line in f if line.strip())
            except Exception:
                pass

            file_findings = self.scan_file(fpath, target_dir)
            all_findings.extend(file_findings)

            if progress_callback:
                rel = os.path.relpath(fpath, target_dir)
                progress_callback(idx, total_files, rel, len(all_findings))

        duration = round(time.time() - start_time, 2)

        result = ScanResult(
            repo_name=repo_name,
            repo_path=target_dir,
            source_type=source_type,
            duration_seconds=duration,
            total_files=total_files,
            scanned_files=total_files,
            lines_of_code=total_loc,
            findings=all_findings,
            folder_counts=folder_counts
        )
        result.calculate_metrics()
        return result
