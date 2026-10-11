"""OWASP A03:2021 - Injection Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A03-001",
        title="SQL Injection via String Formatting or Concatenation",
        category=OWASPCategory.A03,
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        languages=["py", "js", "ts", "php", "java", "go"],
        description="Constructing SQL queries using dynamic string formatting, concatenation, or f-strings allows attackers to alter query logic, bypass authentication, and extract or destroy database records.",
        remediation="Always use parameterized queries (prepared statements) or an ORM with proper query parameter binding.",
        remediation_code="""# Safe parameterized query:
# Python SQLite / DB-API:
cursor.execute("SELECT * FROM users WHERE username = ? AND status = ?", (username, status))

# SQLAlchemy ORM:
user = session.query(User).filter(User.username == username).first()""",
        patterns=[
            r"(?:execute|raw)\s*\(\s*f['\"][^'\"]*SELECT\b.*\{",
            r"(?:execute|raw)\s*\(\s*f['\"][^'\"]*(?:INSERT|UPDATE|DELETE)\b.*\{",
            r"(?:execute|raw)\s*\(\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*%",
            r"(?:execute|raw)\s*\(\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*\.format\(",
            r"(?:execute|raw)\s*\(\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*\+",
            r"\$db->query\s*\(\s*['\"][^'\"]*\$_(?:GET|POST|REQUEST)",
        ]
    ),
    Rule(
        id="SEC-A03-002",
        title="Command Injection via Shell Execution",
        category=OWASPCategory.A03,
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        languages=["py", "js", "ts", "php", "java", "go"],
        description="Passing unvalidated user input into system shell execution functions allows arbitrary operating system command execution, leading to complete host compromise.",
        remediation="Avoid invoking system shells. Use subprocess with an explicit argument list and shell=False, or use dedicated high-level libraries.",
        remediation_code="""# Safe command execution:
import subprocess

# Pass command and arguments as a list with shell=False:
result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, check=True, timeout=5)""",
        patterns=[
            r"os\.system\s*\(\s*(?:f['\"]|.*\+|.*\.format\(|.*%|request\.)",
            r"subprocess\.(?:call|check_call|check_output|Popen|run)\s*\([^)]*shell\s*=\s*True",
            r"child_process\.exec\s*\(\s*`.*\$",
            r"child_process\.exec\s*\([^,]+(?:req\.query|req\.body|req\.params|\+)",
            r"(?:system|exec|passthru|shell_exec)\s*\(\s*\$_(?:GET|POST|REQUEST)",
            r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+",
        ]
    ),
    Rule(
        id="SEC-A03-003",
        title="Cross-Site Scripting (XSS) via Unsanitized Output",
        category=OWASPCategory.A03,
        severity=Severity.HIGH,
        cwe="CWE-79",
        languages=["py", "js", "ts", "html", "php"],
        description="Rendering unescaped user-controlled data into HTML contexts enables Stored or Reflected XSS, allowing attackers to hijack sessions, steal cookies, and perform actions on behalf of victims.",
        remediation="Ensure automatic contextual HTML escaping is enabled. In React, avoid 'dangerouslySetInnerHTML'. In Django/Flask, avoid 'mark_safe' or '|safe' filters on untrusted inputs.",
        remediation_code="""# Safe template rendering:
# In Flask: use render_template with automatic escaping
return render_template("profile.html", username=user_input)

# In React: render safe text elements
return <div>{props.username}</div>;""",
        patterns=[
            r"render_template_string\s*\(\s*f?['\"].*\{.*request\.",
            r"mark_safe\s*\(\s*request\.",
            r"\|\s*safe\b",
            r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:",
            r"\.innerHTML\s*=\s*.*(?:req\.query|req\.body|params|window\.location)",
            r"document\.write\s*\(",
        ]
    ),
    Rule(
        id="SEC-A03-004",
        title="Unsafe Dynamic Code Evaluation (eval / exec)",
        category=OWASPCategory.A03,
        severity=Severity.CRITICAL,
        cwe="CWE-95",
        languages=["py", "js", "ts", "php"],
        description="Executing strings as code using 'eval()' or 'exec()' can permit remote code execution if the input is influenced by external or untrusted sources.",
        remediation="Never execute untrusted input with eval(). For data parsing, use json.loads() or ast.literal_eval() for strictly safe literals.",
        remediation_code="""# Safe alternative for parsing data:
import ast
import json

# For JSON:
data = json.loads(payload)

# For safe Python literals (numbers, strings, tuples, lists, dicts):
safe_data = ast.literal_eval(payload)""",
        patterns=[
            r"\beval\s*\(\s*(?:request\.|req\.|input\(|sys\.argv|\$_(?:GET|POST)|user_)",
            r"\bexec\s*\(\s*(?:request\.|req\.|input\(|sys\.argv|\$_(?:GET|POST)|user_)",
            r"new\s+Function\s*\(\s*.*(?:req\.query|req\.body)",
        ]
    ),
    Rule(
        id="SEC-A03-005",
        title="NoSQL Injection / MongoDB Arbitrary Evaluation",
        category=OWASPCategory.A03,
        severity=Severity.HIGH,
        cwe="CWE-943",
        languages=["py", "js", "ts"],
        description="Using raw JavaScript strings in MongoDB '$where' clauses or unsanitized query parameters allows attackers to inject arbitrary JavaScript expressions on the database server.",
        remediation="Do not use '$where' or dynamic JavaScript query expressions. Use structured query operators and sanitize object parameters with express-mongo-sanitize.",
        remediation_code="""# Safe MongoDB query:
# Use standard operators instead of $where:
collection.find({"username": username, "status": "active"})""",
        patterns=[
            r"['\"]\$where['\"]\s*:\s*(?:f['\"]|.*(?:req\.query|req\.body|\+))",
            r"\.find\s*\(\s*\{\s*\$where\s*:",
        ]
    ),
    Rule(
        id="SEC-A03-006",
        title="JavaScript Prototype Pollution Vulnerability",
        category=OWASPCategory.A03,
        severity=Severity.HIGH,
        cwe="CWE-1321",
        languages=["js", "ts"],
        description="Unsafely merging or assigning user-controlled objects recursively without sanitizing special keys ('__proto__', 'constructor', 'prototype') allows attackers to modify Object.prototype, altering behavior across the entire Node.js runtime.",
        remediation="Validate object keys against '__proto__' and 'constructor', freeze prototypes with Object.freeze(Object.prototype), or use Map data structures.",
        remediation_code="""# Safe object merging:
function safeAssign(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    target[key] = source[key];
  }
  return target;
}""",
        patterns=[
            r"(?:Object\.assign|_\.merge|_\.extend)\s*\([^,]+,\s*(?:req\.body|req\.query)",
            r"\[['\"]__proto__['\"]\]",
        ]
    ),
    Rule(
        id="SEC-A03-007",
        title="XML External Entity (XXE) Injection Vulnerability",
        category=OWASPCategory.A03,
        severity=Severity.HIGH,
        cwe="CWE-611",
        languages=["py", "java", "php", "js"],
        description="Parsing untrusted XML documents with XML parser entity expansion enabled allows attackers to read local files, initiate SSRF attacks, or exhaust system resources.",
        remediation="Disable external entity resolution (DTD processing) in your XML parser, or use safe libraries like Python's 'defusedxml'.",
        remediation_code="""# Safe XML parsing with defusedxml:
import defusedxml.ElementTree as ET

tree = ET.fromstring(untrusted_xml_data)""",
        patterns=[
            r"(?:xml\.etree\.ElementTree|ET|lxml\.etree)\.(?:parse|fromstring)\s*\(",
            r"lxml\.etree\.(?:parse|fromstring|XMLParser)\s*\(",
            r"DocumentBuilderFactory\.newInstance\s*\(",
        ]
    ),
    Rule(
        id="SEC-A03-008",
        title="Regular Expression Denial of Service (ReDoS) Vulnerability",
        category=OWASPCategory.A03,
        severity=Severity.MEDIUM,
        cwe="CWE-1333",
        languages=["py", "js", "ts", "java"],
        description="Regular expressions with nested quantifiers (e.g., (a+)+ or ([a-zA-Z]+)*) suffer from catastrophic polynomial or exponential backtracking when evaluated against non-matching input strings, causing complete CPU denial of service.",
        remediation="Refactor regular expressions to eliminate ambiguous overlapping sub-patterns, or enforce evaluation timeouts using regex engines like Google's re2.",
        remediation_code="""# Safe linear-time regex:
# Avoid nested quantifiers like: (.*a)+
# Instead use non-overlapping anchored tokens:
import re
pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")""",
        patterns=[
            r"r?['\"][^'\"]*\((?:\[[^\]]+\]|[a-zA-Z0-9_\-\.\*])+\+\)\+[^'\"]*['\"]",
            r"r?['\"][^'\"]*\((?:\[[^\]]+\]|[a-zA-Z0-9_\-\.\*])+\*\)\*[^'\"]*['\"]",
        ]
    ),
    Rule(
        id="SEC-A03-009",
        title="Jinja2 Template Engine Autoescape Disabled (XSS Risk)",
        category=OWASPCategory.A03,
        severity=Severity.HIGH,
        cwe="CWE-79",
        languages=["py"],
        description="Initializing Jinja2 Environment with 'autoescape=False' disables automatic HTML entity escaping, allowing any template variable rendering untrusted input to be exploited for Cross-Site Scripting (XSS).",
        remediation="Enable contextual autoescaping: Environment(autoescape=select_autoescape(['html', 'xml']))",
        remediation_code="""# Safe Jinja2 autoescape configuration:
from jinja2 import Environment, select_autoescape

env = Environment(autoescape=select_autoescape(['html', 'xml', 'htm']))""",
        patterns=[
            r"Environment\s*\([^)]*autoescape\s*=\s*False",
        ]
    )
]
