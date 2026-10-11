"""OWASP A01:2021 - Broken Access Control Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A01-001",
        title="Path Traversal via Unvalidated User Input",
        category=OWASPCategory.A01,
        severity=Severity.HIGH,
        cwe="CWE-22",
        languages=["py", "js", "ts", "php", "java", "go"],
        description="Path traversal allows an attacker to access arbitrary files on the server file system by manipulating variables that reference files with dot-dot-slash ('../') sequences.",
        remediation="Validate user input against an allowlist, use os.path.basename(), and verify the resolved path remains within the intended target directory using os.path.realpath() or pathlib.Path.resolve().",
        remediation_code="""# Safe implementation:
from pathlib import Path

safe_base = Path('/safe/directory/').resolve()
requested_path = (safe_base / filename).resolve()
if not requested_path.is_relative_to(safe_base):
    raise PermissionError("Access denied: path traversal detected")
return open(requested_path, 'rb')""",
        patterns=[
            # Python open / send_file with path concat / traversal
            r"(?:open|send_file|send_from_directory)\s*\(\s*(?:request\.(?:args|form|values|GET|POST)\[['\"][^'\"]*path|os\.path\.join\([^)]*request\.(?:args|form|values)\]|f['\"].*\{.*request\.(?:args|form|values))",
            r"(?:open|readFile|readFileSync)\s*\(\s*.*(?:\.\./|__dirname\s*\+\s*['\"][^'\"]*\.\.)",
            r"res\.sendFile\s*\(\s*req\.(?:query|body|params)\.",
            r"include(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST)\[",
        ]
    ),
    Rule(
        id="SEC-A01-002",
        title="Overly Permissive CORS Access-Control-Allow-Origin Wildcard",
        category=OWASPCategory.A01,
        severity=Severity.MEDIUM,
        cwe="CWE-942",
        languages=["py", "js", "ts", "go", "java"],
        description="Configuring 'Access-Control-Allow-Origin' to '*' allows any website to make cross-origin requests to your API, which can lead to sensitive data leakage or unauthorized state modification.",
        remediation="Specify trusted explicit origins instead of using the wildcard '*'. Never reflect the 'Origin' header without strict validation against a whitelist.",
        remediation_code="""# Safe CORS configuration (Flask-CORS / Express):
# Python Flask:
CORS(app, origins=["https://app.yourdomain.com", "https://admin.yourdomain.com"], supports_credentials=True)

# Node.js Express:
app.use(cors({ origin: ['https://app.yourdomain.com'], credentials: true }));""",
        patterns=[
            r"['\"]Access-Control-Allow-Origin['\"]\s*:\s*['\"]\*(?:['\"])?",
            r"res\.setHeader\s*\(\s*['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*",
            r"response\.headers\s*\[\s*['\"]Access-Control-Allow-Origin['\"]\s*\]\s*=\s*['\"]\*",
            r"CORS\s*\(\s*app\s*,\s*resources=\{r\"/.*\":\s*\{\"origins\":\s*\"\*\"\}\}",
            r"allow_origins\s*=\s*\[\s*['\"]\*\s*['\"]\s*\]",
        ]
    ),
    Rule(
        id="SEC-A01-003",
        title="Insecure Direct Object Reference (IDOR) / Missing Authorization Check",
        category=OWASPCategory.A01,
        severity=Severity.HIGH,
        cwe="CWE-639",
        languages=["py", "js", "ts", "php", "java"],
        description="Querying and returning sensitive resources directly using an unvalidated user-supplied ID parameter without checking if the current authenticated user has permission to view that resource.",
        remediation="Always enforce access control checks verifying that the currently logged-in user owns or has permission to access the requested resource ID.",
        remediation_code="""# Safe IDOR mitigation:
@app.route('/account/<account_id>')
@login_required
def view_account(account_id):
    account = Account.query.filter_by(id=account_id, owner_id=current_user.id).first_or_404()
    return render_template('account.html', account=account)""",
        patterns=[
            r"def\s+(?:view|get|delete|update)_(?:user|account|order|profile|invoice)\s*\([^)]*id\):[^:\n]*\n\s+(?:User|Account|Order|Profile|Invoice)\.query\.get\s*\(id\)",
            r"router\.(?:get|post|delete|put)\(['\"]/(?:user|account|order)/:id['\"].*(?:findUnique|findById|findOne)\s*\(\s*\{\s*where:\s*\{\s*id:\s*req\.params\.id\s*\}\s*\}\)",
        ]
    ),
    Rule(
        id="SEC-A01-004",
        title="Excessive File Permissions (Chmod 777 / World Writable)",
        category=OWASPCategory.A01,
        severity=Severity.MEDIUM,
        cwe="CWE-732",
        languages=["py", "js", "ts", "sh", "bash"],
        description="Setting file or directory permissions to 0777 or world-writable creates a broken access control vulnerability where local users and processes can read, modify, or replace critical files.",
        remediation="Use least privilege permissions such as 0600 (owner read/write only) for confidential files, or 0750 for scripts/executables.",
        remediation_code="""# Safe file permissions:
import os
import stat

os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR) # 0600 - Owner read/write only""",
        patterns=[
            r"os\.chmod\s*\([^,]+,\s*(?:0o?777|stat\.S_IRWXU\s*\|\s*stat\.S_IRWXG\s*\|\s*stat\.S_IRWXO)",
            r"chmod\s+(?:-R\s+)?777\b",
            r"fs\.chmod(?:Sync)?\s*\([^,]+,\s*(?:0o?777|['\"]777['\"])",
        ]
    ),
    Rule(
        id="SEC-A01-005",
        title="Insecure Temporary File Creation via tempfile.mktemp()",
        category=OWASPCategory.A01,
        severity=Severity.HIGH,
        cwe="CWE-377",
        languages=["py"],
        description="'tempfile.mktemp()' generates a filename without atomically creating the file, introducing a Time-of-Check to Time-of-Use (TOCTOU) race condition that allows symlink attacks and arbitrary file overwrite.",
        remediation="Use 'tempfile.NamedTemporaryFile()' or 'tempfile.mkstemp()', which atomically creates the file with safe permissions (0600).",
        remediation_code="""# Safe temporary file creation:
import tempfile

with tempfile.NamedTemporaryFile(delete=True) as temp_file:
    temp_file.write(b"secure data")
    temp_file.flush()""",
        patterns=[
            r"tempfile\.mktemp\s*\(",
        ]
    )
]
