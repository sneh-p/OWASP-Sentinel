"""OWASP A07:2021 - Identification and Authentication Failures Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A07-001",
        title="Insecure Cookie Attributes (Missing HttpOnly / Secure / SameSite)",
        category=OWASPCategory.A07,
        severity=Severity.MEDIUM,
        cwe="CWE-1004",
        languages=["py", "js", "ts", "php"],
        description="Setting session or authentication cookies without the 'HttpOnly' flag allows JavaScript access (vulnerable to XSS theft). Omitting 'Secure' allows interception over unencrypted HTTP, and omitting 'SameSite' allows Cross-Site Request Forgery (CSRF).",
        remediation="Always set 'httponly=True', 'secure=True', and 'samesite=\"Lax\"' or '\"Strict\"' when issuing authentication cookies.",
        remediation_code="""# Safe session cookie configuration:
response.set_cookie(
    key='session_id',
    value=session_token,
    httponly=True,
    secure=True,
    samesite='Lax',
    max_age=3600
)""",
        patterns=[
            r"set_cookie\s*\([^)]*httponly\s*=\s*False",
            r"set_cookie\s*\([^)]*secure\s*=\s*False",
            r"set_cookie\s*\((?![^)]*httponly)[^)]*\)",
            r"res\.cookie\s*\([^)]*httpOnly:\s*false",
            r"res\.cookie\s*\((?![^)]*httpOnly)[^)]*\)",
        ]
    ),
    Rule(
        id="SEC-A07-002",
        title="Timing Attack via Non-Constant Time Password/Secret Comparison",
        category=OWASPCategory.A07,
        severity=Severity.MEDIUM,
        cwe="CWE-208",
        languages=["py", "js", "ts", "go", "java"],
        description="Comparing password hashes, HMAC tokens, or secret tokens using standard equality operators ('==' or '===') leaks character match timing, enabling timing side-channel attacks.",
        remediation="Use constant-time comparison functions such as Python's 'hmac.compare_digest()' or Node's 'crypto.timingSafeEqual()'.",
        remediation_code="""# Safe constant-time comparison:
import hmac

if not hmac.compare_digest(user_provided_token, expected_token):
    raise PermissionError("Invalid authentication token")""",
        patterns=[
            r"(?:password_hash|token_hash|auth_token|signature|stored_hash)\s*==\s*",
            r"if\s+password\s*==\s*user\.password\b",
            r"if\s*\(\s*req\.headers\['authorization'\]\s*===?\s*",
        ]
    ),
    Rule(
        id="SEC-A07-003",
        title="Weak Password Policy Minimum Length (< 8 Characters)",
        category=OWASPCategory.A07,
        severity=Severity.LOW,
        cwe="CWE-521",
        languages=["py", "js", "ts"],
        description="Allowing passwords shorter than 8 characters makes user accounts susceptible to dictionary and brute force guessing.",
        remediation="Enforce a minimum password length of at least 10-12 characters, and consider checking against lists of known breached passwords (e.g. haveibeenpwned).",
        remediation_code="""# Safe password policy:
if len(password) < 12:
    raise ValueError("Password must be at least 12 characters long.")""",
        patterns=[
            r"len\s*\(\s*password\s*\)\s*<\s*[1-7]\b",
            r"password\.length\s*<\s*[1-7]\b",
        ]
    ),
    Rule(
        id="SEC-A07-004",
        title="Hardcoded Authentication Bypass or Master Credential",
        category=OWASPCategory.A07,
        severity=Severity.CRITICAL,
        cwe="CWE-259",
        languages=["py", "js", "ts", "php"],
        description="Backdoor or master credentials hardcoded in authentication handlers allow anyone knowing the credential to bypass proper identity checks.",
        remediation="Remove all hardcoded credentials and backdoor logic. Authenticate exclusively against validated user credential stores.",
        remediation_code="""# Authentic verification:
user = User.query.filter_by(username=username).first()
if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
    raise AuthenticationFailed("Invalid username or password")""",
        patterns=[
            r"if\s+.*password\s*==\s*['\"](?:secret|master|admin|backdoor)['\"]",
            r"if\s+.*(?:username|user)\s*==\s*['\"]admin['\"]\s+and\s+password\s*==",
        ]
    ),
    Rule(
        id="SEC-A07-005",
        title="Insecure JWT Configuration Permitting 'none' Algorithm",
        category=OWASPCategory.A07,
        severity=Severity.CRITICAL,
        cwe="CWE-327",
        languages=["js", "ts", "py"],
        description="Allowing the 'none' algorithm in JWT signature verification permits attackers to forge arbitrary tokens with forged claims without knowing the secret key.",
        remediation="Strictly specify allowed algorithms (e.g. algorithms=['HS256'] or ['RS256']) and never permit 'none'.",
        remediation_code="""# Safe JWT verification:
jwt.verify(token, secretKey, { algorithms: ['HS256'] });""",
        patterns=[
            r"algorithms\s*:\s*\[\s*['\"]none['\"]\s*\]",
            r"algorithms\s*=\s*\[\s*['\"]none['\"]\s*\]",
            r"verify_signature\s*=\s*False",
        ]
    )
]
