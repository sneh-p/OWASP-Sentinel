"""Python Abstract Syntax Tree (AST) Security Analyzer."""

import ast
from typing import List, Optional
from ..models import Finding, OWASPCategory, Severity


class PythonASTAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.findings: List[Finding] = []

    def _get_snippet(self, lineno: int, context: int = 2) -> str:
        start = max(0, lineno - 1 - context)
        end = min(len(self.lines), lineno + context)
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == lineno - 1 else "    "
            line_content = self.lines[i] if i < len(self.lines) else ""
            snippet_lines.append(f"{i + 1:4d} | {prefix}{line_content}")
        return "\n".join(snippet_lines)

    def _get_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = ""
        full_call = ""

        # Extract function call name
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            full_call = func_name
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            val = node.func.value
            if isinstance(val, ast.Name):
                full_call = f"{val.id}.{func_name}"
            elif isinstance(val, ast.Attribute):
                if isinstance(val.value, ast.Name):
                    full_call = f"{val.value.id}.{val.attr}.{func_name}"

        lineno = getattr(node, "lineno", 1)

        # 1. eval() or exec()
        if func_name in ("eval", "exec") and node.args:
            # Check if argument is a constant or variable/expression
            if not isinstance(node.args[0], ast.Constant):
                self.findings.append(Finding(
                    rule_id="SEC-A03-004",
                    title=f"Dynamic Code Evaluation via {func_name}()",
                    category=OWASPCategory.A03.value,
                    severity=Severity.CRITICAL.value,
                    cwe="CWE-95",
                    file_path=self.file_path,
                    line_number=lineno,
                    matched_line=self._get_line(lineno),
                    code_snippet=self._get_snippet(lineno),
                    description=f"Using '{func_name}()' to evaluate expressions or statements can result in remote code execution if input is tainted.",
                    remediation=f"Avoid using {func_name}(). Use ast.literal_eval() for safely parsing Python literals or json.loads() for JSON data.",
                ))

        # 2. os.system()
        if full_call == "os.system" and node.args:
            self.findings.append(Finding(
                rule_id="SEC-A03-002",
                title="Command Injection via os.system()",
                category=OWASPCategory.A03.value,
                severity=Severity.CRITICAL.value,
                cwe="CWE-78",
                file_path=self.file_path,
                line_number=lineno,
                matched_line=self._get_line(lineno),
                code_snippet=self._get_snippet(lineno),
                description="'os.system()' passes arguments directly to the host shell, making the application vulnerable to command injection if user input is included.",
                remediation="Use subprocess.run(['cmd', 'arg1'], shell=False) with parameterized arguments instead of os.system().",
            ))

        # 3. subprocess calls with shell=True
        if "subprocess" in full_call:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(Finding(
                        rule_id="SEC-A03-002",
                        title=f"Subprocess Execution with shell=True in {full_call}()",
                        category=OWASPCategory.A03.value,
                        severity=Severity.CRITICAL.value,
                        cwe="CWE-78",
                        file_path=self.file_path,
                        line_number=lineno,
                        matched_line=self._get_line(lineno),
                        code_snippet=self._get_snippet(lineno),
                        description=f"Calling '{full_call}' with 'shell=True' invokes the system shell and enables command injection vulnerabilities.",
                        remediation="Set shell=False and pass arguments as a list: subprocess.run(['executable', arg1, arg2], check=True).",
                    ))

        # 4. SQL Injection via cursor.execute / connection.execute with dynamic strings
        if func_name in ("execute", "raw") and node.args:
            first_arg = node.args[0]
            # Check for JoinedStr (f-string)
            is_insecure = False
            reason = ""
            if isinstance(first_arg, ast.JoinedStr):
                is_insecure = True
                reason = "Formatted string literal (f-string)"
            # Check for BinOp % or +
            elif isinstance(first_arg, ast.BinOp):
                if isinstance(first_arg.op, (ast.Mod, ast.Add)):
                    is_insecure = True
                    reason = "String concatenation / formatting operator"
            # Check for .format() call
            elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                is_insecure = True
                reason = "str.format() method"

            if is_insecure:
                self.findings.append(Finding(
                    rule_id="SEC-A03-001",
                    title=f"SQL Query Formatted Dynamically ({reason}) in {full_call or func_name}()",
                    category=OWASPCategory.A03.value,
                    severity=Severity.CRITICAL.value,
                    cwe="CWE-89",
                    file_path=self.file_path,
                    line_number=lineno,
                    matched_line=self._get_line(lineno),
                    code_snippet=self._get_snippet(lineno),
                    description=f"Dynamically formatting SQL strings using {reason} permits SQL injection attacks.",
                    remediation="Use parameterized queries with database placeholders (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))",
                ))

        # 5. Insecure Deserialization via pickle.loads or pickle.load
        if "pickle.load" in full_call or "_pickle.load" in full_call:
            self.findings.append(Finding(
                rule_id="SEC-A08-001",
                title=f"Insecure Deserialization via {full_call}()",
                category=OWASPCategory.A08.value,
                severity=Severity.CRITICAL.value,
                cwe="CWE-502",
                file_path=self.file_path,
                line_number=lineno,
                matched_line=self._get_line(lineno),
                code_snippet=self._get_snippet(lineno),
                description=f"Loading serialized objects via '{full_call}' can execute arbitrary code during object reconstruction.",
                remediation="Never unpickle untrusted data. Use safer data interchange formats like JSON, Protobuf, or MsgPack.",
            ))

        # 6. yaml.load without SafeLoader
        if full_call == "yaml.load":
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    # Check if value is yaml.SafeLoader or SafeLoader
                    if isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader":
                        has_safe_loader = True
                    elif isinstance(kw.value, ast.Name) and kw.value.id == "SafeLoader":
                        has_safe_loader = True

            if not has_safe_loader:
                self.findings.append(Finding(
                    rule_id="SEC-A08-002",
                    title="Unsafe YAML Deserialization via yaml.load()",
                    category=OWASPCategory.A08.value,
                    severity=Severity.CRITICAL.value,
                    cwe="CWE-502",
                    file_path=self.file_path,
                    line_number=lineno,
                    matched_line=self._get_line(lineno),
                    code_snippet=self._get_snippet(lineno),
                    description="Calling 'yaml.load()' without 'Loader=yaml.SafeLoader' allows arbitrary code execution via YAML object constructors.",
                    remediation="Use 'yaml.safe_load(data)' or pass 'Loader=yaml.SafeLoader'.",
                ))

        # 7. requests with verify=False
        if "requests." in full_call:
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.findings.append(Finding(
                        rule_id="SEC-A02-004",
                        title=f"TLS/SSL Certificate Verification Disabled in {full_call}()",
                        category=OWASPCategory.A02.value,
                        severity=Severity.CRITICAL.value,
                        cwe="CWE-295",
                        file_path=self.file_path,
                        line_number=lineno,
                        matched_line=self._get_line(lineno),
                        code_snippet=self._get_snippet(lineno),
                        description="Disabling TLS certificate validation ('verify=False') leaves connections open to machine-in-the-middle (MitM) eavesdropping and tampering.",
                        remediation="Enable certificate verification ('verify=True') or configure a custom trusted CA bundle.",
                    ))

        # 8. Flask app.run with debug=True
        if func_name == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(Finding(
                        rule_id="SEC-A05-001",
                        title="Flask Application Started with debug=True",
                        category=OWASPCategory.A05.value,
                        severity=Severity.HIGH.value,
                        cwe="CWE-489",
                        file_path=self.file_path,
                        line_number=lineno,
                        matched_line=self._get_line(lineno),
                        code_snippet=self._get_snippet(lineno),
                        description="Running Flask with 'debug=True' activates the interactive Werkzeug debugger, which may allow remote code execution via PIN bypass in production.",
                        remediation="Set debug=False or control it through an environment variable like FLASK_DEBUG defaulting to False.",
                    ))

        # 9. render_template_string with f-string or formatting
        if func_name == "render_template_string" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.JoinedStr) or isinstance(arg, ast.BinOp):
                self.findings.append(Finding(
                    rule_id="SEC-A03-003",
                    title="Server-Side Template Injection (SSTI) / XSS in render_template_string",
                    category=OWASPCategory.A03.value,
                    severity=Severity.HIGH.value,
                    cwe="CWE-1336",
                    file_path=self.file_path,
                    line_number=lineno,
                    matched_line=self._get_line(lineno),
                    code_snippet=self._get_snippet(lineno),
                    description="Interpolating dynamic variables directly into the template string enables Server-Side Template Injection (SSTI) and XSS.",
                    remediation="Pass variables as template context arguments rather than concatenating them into the template string.",
                ))

        # 10. tempfile.mktemp()
        if "tempfile.mktemp" in full_call or (func_name == "mktemp" and "tempfile" in full_call):
            self.findings.append(Finding(
                rule_id="SEC-A01-005",
                title="Insecure Temporary File Creation via tempfile.mktemp()",
                category=OWASPCategory.A01.value,
                severity=Severity.HIGH.value,
                cwe="CWE-377",
                file_path=self.file_path,
                line_number=lineno,
                matched_line=self._get_line(lineno),
                code_snippet=self._get_snippet(lineno),
                description="'tempfile.mktemp()' is vulnerable to race conditions (TOCTOU) allowing symlink attacks and arbitrary file overwrite.",
                remediation="Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead.",
            ))

        # 11. Jinja2 Environment with autoescape=False
        if func_name == "Environment" or "jinja2.Environment" in full_call:
            for kw in node.keywords:
                if kw.arg == "autoescape" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.findings.append(Finding(
                        rule_id="SEC-A03-009",
                        title="Jinja2 Template Engine Autoescape Disabled",
                        category=OWASPCategory.A03.value,
                        severity=Severity.HIGH.value,
                        cwe="CWE-79",
                        file_path=self.file_path,
                        line_number=lineno,
                        matched_line=self._get_line(lineno),
                        code_snippet=self._get_snippet(lineno),
                        description="Disabling autoescape in Jinja2 Environment exposes all rendered variables to Cross-Site Scripting (XSS).",
                        remediation="Enable contextual autoescaping using select_autoescape(['html', 'xml']).",
                    ))

        # 12. Insecure XML Parsing (XXE)
        if "xml.etree.ElementTree" in full_call or "lxml.etree" in full_call or full_call.startswith("ET."):
            if func_name in ("parse", "fromstring", "XML"):
                self.findings.append(Finding(
                    rule_id="SEC-A03-007",
                    title=f"XML Parsing via {full_call}() (Potential XXE)",
                    category=OWASPCategory.A03.value,
                    severity=Severity.HIGH.value,
                    cwe="CWE-611",
                    file_path=self.file_path,
                    line_number=lineno,
                    matched_line=self._get_line(lineno),
                    code_snippet=self._get_snippet(lineno),
                    description="Parsing XML without disabling entity expansion permits XML External Entity (XXE) file disclosure and SSRF.",
                    remediation="Use defusedxml (defusedxml.ElementTree) or configure parser with resolve_entities=False.",
                ))

        # 13. Mass Assignment via update(**dict)
        if func_name == "update":
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    self.findings.append(Finding(
                        rule_id="SEC-API-001",
                        title="Potential Mass Assignment via update(**dict)",
                        category=OWASPCategory.A04.value,
                        severity=Severity.HIGH.value,
                        cwe="CWE-915",
                        file_path=self.file_path,
                        line_number=lineno,
                        matched_line=self._get_line(lineno),
                        code_snippet=self._get_snippet(lineno),
                        description="Passing unpacked dictionaries directly into .update() permits overwriting protected internal model attributes.",
                        remediation="Explicitly specify and validate permitted model fields before updating.",
                    ))

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        # Detect bare except or except Exception with solely `pass`
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            lineno = getattr(node, "lineno", 1)
            self.findings.append(Finding(
                rule_id="SEC-A09-002",
                title="Silent Exception Swallowing (try/except ... pass)",
                category=OWASPCategory.A09.value,
                severity=Severity.LOW.value,
                cwe="CWE-391",
                file_path=self.file_path,
                line_number=lineno,
                matched_line=self._get_line(lineno),
                code_snippet=self._get_snippet(lineno),
                description="Swallowing exceptions silently with 'pass' disables security auditing, conceals errors, and prevents intrusion detection.",
                remediation="Log the exception with logging.exception() or logger.error() before handling or re-raising.",
            ))
        self.generic_visit(node)


def analyze_python_ast(file_path: str, source_code: str) -> List[Finding]:
    """Parse and analyze Python source code using AST."""
    try:
        tree = ast.parse(source_code, filename=file_path)
        analyzer = PythonASTAnalyzer(file_path, source_code)
        analyzer.visit(tree)
        return analyzer.findings
    except SyntaxError:
        # File has invalid syntax (e.g., Python 2 or template)
        return []
    except Exception:
        return []
