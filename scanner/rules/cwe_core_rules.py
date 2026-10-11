"""CWE Top 25 Core Systems and Software Weaknesses.

Covers non-web vulnerabilities and systems-level flaws from the MITRE CWE Top 25:
- CWE-476: NULL Pointer Dereference (Rank #12)
- CWE-190: Integer Overflow or Wraparound (Rank #14)
- CWE-362: Race Condition / TOCTOU (Rank #21)
- CWE-276: Incorrect Default Permissions (Rank #25)
- CWE-377: Insecure Temporary File Creation
- CWE-676: Use of Potentially Dangerous Functions
- CWE-330: Use of Insufficiently Random Values
- CWE-400: Uncontrolled Resource Consumption / ReDoS
"""

from ..models import Rule, SecurityCategory, Severity

RULES = [
    Rule(
        id="CWE-476-001",
        title="Unchecked Return Value / Potential NULL Pointer Dereference (CWE Top 25 #12)",
        category=SecurityCategory.CWE_TOP25,
        severity=Severity.HIGH,
        cwe="CWE-476",
        languages=["c", "cpp", "java", "go", "cs"],
        description="Dereferencing pointers or objects returned from lookups without checking for NULL/nullptr leads to segmentation faults, crashes, or denial of service.",
        remediation="Always perform null checks on object references and pointer returns prior to member access or dereferencing.",
        remediation_code="""// Safe null check pattern:
char *buf = (char *)malloc(size);
if (buf == NULL) {
    return ERROR_OUT_OF_MEMORY;
}
memset(buf, 0, size);""",
        patterns=[
            r"\bmalloc\s*\([^)]+\)\s*;[^\n]*\n\s*(?!(?:if\s*\([^)]*==\s*NULL|\bif\s*\(!))\w+->",
            r"\b[A-Za-z0-9_]+\.get\([^)]+\)\.[A-Za-z0-9_]+\(",
        ],
        standard="CWE Top 25",
        cwe_rank=12,
        frameworks=["CWE Top 25", "System Safety"],
    ),
    Rule(
        id="CWE-190-001",
        title="Integer Overflow or Unsafe Numeric Wraparound (CWE Top 25 #14)",
        category=SecurityCategory.CWE_TOP25,
        severity=Severity.HIGH,
        cwe="CWE-190",
        languages=["c", "cpp", "go", "java"],
        description="Performing arithmetic operations on untrusted integer values without boundary validation can wrap around, leading to undersized memory allocations, buffer overruns, or infinite loops.",
        remediation="Use safe math libraries or validate bounds before arithmetic operations.",
        remediation_code="""// Safe integer addition check:
if (a > INT_MAX - b) {
    return OVERFLOW_ERROR;
}
int c = a + b;""",
        patterns=[
            r"\bmalloc\s*\(\s*(\w+)\s*\*\s*sizeof\s*\(",
            r"\bcalloc\s*\(\s*\w+\s*\*\s*\w+\s*,",
        ],
        standard="CWE Top 25",
        cwe_rank=14,
        frameworks=["CWE Top 25", "System Safety"],
    ),
    Rule(
        id="CWE-362-001",
        title="Time-of-Check to Time-of-Use (TOCTOU) Race Condition (CWE Top 25 #21)",
        category=SecurityCategory.SYSTEM_SAFETY,
        severity=Severity.MEDIUM,
        cwe="CWE-362",
        languages=["py", "c", "cpp", "go"],
        description="Checking file existence or permissions and then accessing the file in a separate call creates a race window where an adversary can replace the file with a symbolic link.",
        remediation="Use atomic file system operations (e.g. 'os.open' with O_CREAT | O_EXCL, or handle FileNotFoundError/FileExistsError directly in try/except blocks).",
        remediation_code="""# Safe atomic file operation (Python):
try:
    with open(filepath, 'x') as f: # 'x' ensures atomic exclusive creation
        f.write(data)
except FileExistsError:
    handle_conflict()""",
        patterns=[
            r"if\s+os\.path\.exists\([^)]+\):[^\n]*\n\s*(?:with\s+)?open\(",
            r"if\s+os\.path\.isfile\([^)]+\):[^\n]*\n\s*os\.remove\(",
            r"access\s*\([^,]+,\s*[FRW]_OK\)\s*==\s*0[^\n]*\n[^\n]*open\(",
        ],
        standard="CWE Top 25",
        cwe_rank=21,
        frameworks=["CWE Top 25", "System Safety"],
    ),
    Rule(
        id="CWE-276-001",
        title="Incorrect Default Permissions - World-Writable Mode 0777 (CWE Top 25 #25)",
        category=SecurityCategory.SYSTEM_SAFETY,
        severity=Severity.HIGH,
        cwe="CWE-276",
        languages=["py", "sh", "bash", "js", "ts", "go", "c"],
        description="Setting file or directory permissions to 0777 or world-writable allows any local user on the machine to modify, replace, or execute the file, enabling privilege escalation.",
        remediation="Grant strictly necessary permissions (e.g. 0600 for sensitive user files, 0700 or 0750 for directories).",
        remediation_code="""# Safe restrictive file permissions:
os.chmod(filepath, 0o600) # Owner read & write only""",
        patterns=[
            r"chmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b",
            r"os\.chmod\([^,]+,\s*(?:0o777|0777|stat\.S_IRWXU\s*\|\s*stat\.S_IRWXG\s*\|\s*stat\.S_IRWXO)\)",
            r"fs\.chmod(?:Sync)?\([^,]+,\s*(?:0o777|0777|'777')\)",
        ],
        standard="CWE Top 25",
        cwe_rank=25,
        frameworks=["CWE Top 25", "System Safety"],
    ),
    Rule(
        id="CWE-377-001",
        title="Insecure Temporary File Creation via Predictable Path",
        category=SecurityCategory.SYSTEM_SAFETY,
        severity=Severity.MEDIUM,
        cwe="CWE-377",
        languages=["py", "c", "cpp", "sh", "bash"],
        description="Creating temporary files using predictable paths (such as /tmp/xyz or mktemp) allows local attackers to pre-create symlinks pointing to sensitive files (symlink attack) to overwrite arbitrary files.",
        remediation="Use secure, random temporary file primitives such as Python's 'tempfile.NamedTemporaryFile()' or C's 'mkstemp()'.",
        remediation_code="""# Safe temporary file:
import tempfile
with tempfile.NamedTemporaryFile(delete=True) as tmp:
    tmp.write(b"data")""",
        patterns=[
            r"tempfile\.mktemp\b",
            r"['\"]\/tmp\/[a-zA-Z0-9_\-\.]+['\"]",
            r"\bmktemp\s+-(?:u|q)\b",
        ],
        standard="CWE Top 25",
        frameworks=["CWE Top 25", "System Safety"],
    ),
    Rule(
        id="CWE-676-001",
        title="Use of Dangerous Legacy Function Prone to Buffer Overflows",
        category=SecurityCategory.SYSTEM_SAFETY,
        severity=Severity.HIGH,
        cwe="CWE-676",
        languages=["c", "cpp"],
        description="Legacy C library functions like gets(), strcpy(), and strcat() do not check buffer bounds, making applications vulnerable to stack-based buffer overflows.",
        remediation="Use safe, bounds-checked alternatives such as fgets(), strncpy(), strlcpy(), or snprintf().",
        remediation_code="""// Safe bounds-checked copy:
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';""",
        patterns=[
            r"\bgets\s*\(",
            r"\bstrcpy\s*\(",
            r"\bstrcat\s*\(",
            r"\bsprintf\s*\(\s*\w+\s*,",
        ],
        standard="CWE Top 25",
        frameworks=["CWE Top 25", "System Safety"],
    ),
    Rule(
        id="CWE-330-001",
        title="Use of Insufficiently Random Values for Security Contexts",
        category=SecurityCategory.CWE_TOP25,
        severity=Severity.MEDIUM,
        cwe="CWE-330",
        languages=["py", "js", "ts", "java", "php"],
        description="Using pseudo-random number generators (PRNGs) like 'random.random()' or 'Math.random()' for security-sensitive tokens, passwords, or salts is insecure because their state can be predicted.",
        remediation="Use a cryptographically secure pseudo-random number generator (CSPRNG), such as Python's 'secrets' module or 'crypto.getRandomValues()' in JavaScript.",
        remediation_code="""# Python CSPRNG:
import secrets
token = secrets.token_urlsafe(32)

# Node.js CSPRNG:
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');""",
        patterns=[
            r"(?:session|token|auth|key|secret|password|nonce)\w*\s*=\s*(?:str\()?random\.random\(\)",
            r"(?:session|token|auth|key|secret|password|nonce)\w*\s*=\s*Math\.random\(\)",
            r"rand\s*\(\s*\)\s*%\s*\d+",
        ],
        standard="CWE Top 25",
        frameworks=["CWE Top 25", "Secrets & Key Protection"],
    ),
    Rule(
        id="CWE-400-001",
        title="Uncontrolled Resource Consumption / Potential ReDoS Pattern",
        category=SecurityCategory.SYSTEM_SAFETY,
        severity=Severity.LOW,
        cwe="CWE-400",
        languages=["py", "js", "ts", "java"],
        description="Regular expressions with nested quantifiers (e.g. (a+)+ or (x*)*) have exponential worst-case backtracking, causing server thread starvation and Regular Expression Denial of Service (ReDoS).",
        remediation="Rewrite regular expressions without overlapping nested quantifiers, or enforce regex execution timeouts.",
        remediation_code="""# Avoid nested repetition:
# Unsafe: r"^(a+)+$"
# Safe:   r"^a+$" """,
        patterns=[
            r"r?['\"][^'\"]*\([a-zA-Z0-9_\-\.\*]+\+\)\+[^'\"]*['\"]",
            r"r?['\"][^'\"]*\([a-zA-Z0-9_\-\.\+]+\*\)\*[^'\"]*['\"]",
        ],
        standard="CWE Top 25",
        frameworks=["CWE Top 25", "System Safety"],
    ),
]
