"""OWASP A04:2021 - Insecure Design Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A04-001",
        title="Client-Side Trust / Business Logic Parameter Tampering",
        category=OWASPCategory.A04,
        severity=Severity.HIGH,
        cwe="CWE-602",
        languages=["py", "js", "ts"],
        description="Relying on client-supplied parameters for authoritative values like 'price', 'discount', 'role', or 'is_admin' permits attackers to modify transaction values or elevate privileges.",
        remediation="Always calculate pricing, discounts, and permissions on the server using trusted database records. Never accept sensitive authority values directly from client payloads.",
        remediation_code="""# Safe pricing and permission enforcement:
# Look up price strictly from database:
item = Product.query.get_or_404(product_id)
total = item.price * quantity # Price is taken from database, not client request!""",
        patterns=[
            r"(?:price|amount|total|is_admin|role|balance)\s*=\s*(?:request\.(?:form|json|values|args)|req\.(?:body|query))\[['\"](?:price|amount|total|is_admin|role|balance)['\"]",
            r"User\.create\s*\(\s*.*req\.body\s*\)",
        ]
    ),
    Rule(
        id="SEC-A04-002",
        title="Missing Rate Limiting on Authentication Route",
        category=OWASPCategory.A04,
        severity=Severity.MEDIUM,
        cwe="CWE-307",
        languages=["py", "js", "ts"],
        description="Login, password reset, or OTP verification endpoints without rate limiting are susceptible to credential stuffing and automated brute force attacks.",
        remediation="Implement rate limiting on all authentication and sensitive endpoints using tools like Flask-Limiter, express-rate-limit, or reverse proxy rate limiters.",
        remediation_code="""# Safe rate limiting with Flask-Limiter:
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic
    pass""",
        patterns=[
            r"@app\.route\s*\(['\"]/(?:login|signin|reset-password|forgot-password)['\"].*\)[^\n]*\n(?:(?!@limiter).)*\ndef\s+(?:login|signin|reset_password)\(",
        ]
    ),
    Rule(
        id="SEC-A04-003",
        title="Insecure / Missing Expiration on Security Tokens",
        category=OWASPCategory.A04,
        severity=Severity.MEDIUM,
        cwe="CWE-613",
        languages=["py", "js", "ts"],
        description="Generating password reset or authentication tokens without an expiration timestamp allows replay attacks indefinitely if tokens are intercepted.",
        remediation="Enforce short-lived token expiration (e.g. 15 minutes for password resets) using itsdangerous.URLSafeTimedSerializer or JWT with explicit 'exp' claim.",
        remediation_code="""# Safe timed token generation:
from itsdangerous import URLSafeTimedSerializer

serializer = URLSafeTimedSerializer(SECRET_KEY)
token = serializer.dumps(user_email, salt='reset-password')
# Verify with max_age (e.g. 900 seconds = 15 mins):
email = serializer.loads(token, salt='reset-password', max_age=900)""",
        patterns=[
            r"jwt\.sign\s*\(\s*\{[^}]*\}\s*,\s*[^,)]+\s*\)",  # jwt.sign without expiresIn option
            r"def\s+create_reset_token\([^)]*\):[^:\n]*\n\s+(?:return|token\s*=)\s*hashlib\.",
        ]
    )
]
