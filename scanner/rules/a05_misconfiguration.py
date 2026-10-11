"""OWASP A05:2021 - Security Misconfiguration Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A05-001",
        title="Debug Mode Enabled in Application Configuration",
        category=OWASPCategory.A05,
        severity=Severity.HIGH,
        cwe="CWE-489",
        languages=["py", "js", "ts", "json", "yml", "yaml", "env", "php"],
        description="Running an application with debug mode enabled exposes interactive debuggers (which may allow remote code execution, e.g., Werkzeug PIN bypass), detailed environment variables, and stack traces.",
        remediation="Ensure debug mode is disabled in production environments. Load DEBUG flags from environment variables and default to False.",
        remediation_code="""# Safe production configuration:
import os

DEBUG = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")
app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=DEBUG)""",
        patterns=[
            r"app\.run\s*\([^)]*debug\s*=\s*True",
            r"DEBUG\s*=\s*True\b",
            r"['\"]DEBUG['\"]\s*:\s*True\b",
            r"display_errors\s*=\s*(?:On|1)\b",
            r"NODE_ENV\s*:\s*['\"]development['\"]",
        ]
    ),
    Rule(
        id="SEC-A05-002",
        title="Detailed Stack Trace Leaked to Client",
        category=OWASPCategory.A05,
        severity=Severity.MEDIUM,
        cwe="CWE-209",
        languages=["py", "js", "ts", "java", "php"],
        description="Returning internal exceptions or raw stack traces to the client discloses sensitive infrastructure details, file paths, framework versions, and database schemas.",
        remediation="Catch exceptions globally, log details internally on the server, and return generic user-friendly error messages (e.g., 'An internal error occurred') to the client.",
        remediation_code="""# Safe error handling:
import logging

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    logging.exception("Unhandled server exception: %s", error)
    return {"error": "Internal server error", "code": 500}, 500""",
        patterns=[
            r"return\s+.*(?:traceback\.format_exc\(\)|str\(e\)|err\.stack)",
            r"res\.status\(500\)\.send\s*\(\s*(?:err\.stack|err\.message|error\.stack)\)",
            r"res\.json\s*\(\s*\{[^}]*(?:stack:\s*err\.stack|error:\s*err\.stack)",
        ]
    ),
    Rule(
        id="SEC-A05-003",
        title="Missing Security Headers (X-Frame-Options, CSP, HSTS)",
        category=OWASPCategory.A05,
        severity=Severity.LOW,
        cwe="CWE-693",
        languages=["py", "js", "ts", "conf"],
        description="Failing to set defensive HTTP headers leaves web applications vulnerable to Clickjacking (lack of X-Frame-Options), XSS and injection (lack of Content-Security-Policy), and MitM downgrades (lack of Strict-Transport-Security).",
        remediation="Use security middleware such as 'helmet' (Express) or 'flask-talisman' (Flask) to enforce modern security headers automatically.",
        remediation_code="""# Safe security headers:
# In Flask:
from flask_talisman import Talisman
Talisman(app, content_security_policy=csp_dict)

# In Express:
const helmet = require('helmet');
app.use(helmet());""",
        patterns=[
            r"X-Frame-Options:\s*ALLOWALL",
            r"frame-ancestors\s+'\*'",
        ]
    ),
    Rule(
        id="SEC-A05-004",
        title="Default Credentials or Insecure Default Admin Setting",
        category=OWASPCategory.A05,
        severity=Severity.HIGH,
        cwe="CWE-1188",
        languages=["py", "js", "ts", "json", "yml", "yaml", "env"],
        description="Using default administrative usernames and passwords (such as admin/admin or root/root) allows attackers to gain administrative access without credentials guessing.",
        remediation="Force unique password generation upon deployment or prompt the administrator to set credentials during the initial setup wizard.",
        remediation_code="""# Require strong non-default credentials:
ADMIN_PASSWORD = os.environ.get("ADMIN_INITIAL_PASSWORD")
if not ADMIN_PASSWORD or ADMIN_PASSWORD in ["admin", "root", "password", "123456"]:
    raise ValueError("Insecure default password detected. Please set a strong ADMIN_INITIAL_PASSWORD.")""",
        patterns=[
            r"(?i)['\"](?:admin|root|master)['\"]\s*:\s*['\"](?:admin|root|password|123456|toor|admin123)['\"]",
            r"(?i)(?:DEFAULT_PASSWORD|DEFAULT_PASS)\s*=\s*['\"][^'\"]+['\"]",
        ]
    ),
    Rule(
        id="SEC-A05-005",
        title="Dockerfile Running as Root / Missing Non-Root USER Instruction",
        category=OWASPCategory.A05,
        severity=Severity.HIGH,
        cwe="CWE-250",
        languages=["dockerfile", "Dockerfile"],
        description="Executing container processes as the default root user compromises host containment if a breakout vulnerability exists.",
        remediation="Create a dedicated unprivileged user (e.g., appuser) and specify 'USER appuser' in your Dockerfile before the entrypoint.",
        remediation_code="""# Safe non-root Dockerfile user:
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser""",
        patterns=[
            r"^USER\s+root\b",
        ]
    )
]
