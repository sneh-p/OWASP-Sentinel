"""OWASP API Security Top 10 Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-API-001",
        title="Mass Assignment / Over-posting Vulnerability",
        category=OWASPCategory.A04,
        severity=Severity.HIGH,
        cwe="CWE-915",
        languages=["py", "js", "ts", "php", "java"],
        description="Binding client-supplied request payloads directly into data models without field allowlisting (e.g. User.update(**request.json) or User.create(req.body)) permits attackers to overwrite sensitive internal properties like 'is_admin', 'role', or 'account_balance'.",
        remediation="Use explicit schema validation (Pydantic, Marshmallow, Joi, Zod) or explicitly extract permitted fields: user.update({name: req.body.name, email: req.body.email}).",
        remediation_code="""# Safe explicit field extraction:
data = request.get_json()
user.name = data.get("name")
user.bio = data.get("bio")
# NEVER: user.update(**data)""",
        patterns=[
            r"\.update\s*\(\s*\*\*(?:request\.(?:json|form|values)|req\.body)",
            r"User\.create\s*\(\s*\*\*(?:request\.(?:json|form|values)|req\.body)",
            r"(?:User|Account|Profile)\.(?:update|create|build)\s*\(\s*req\.body\s*\)",
        ]
    ),
    Rule(
        id="SEC-API-002",
        title="Unrestricted Resource Consumption (Unbounded Database Query)",
        category=OWASPCategory.A04,
        severity=Severity.MEDIUM,
        cwe="CWE-770",
        languages=["py", "js", "ts"],
        description="Fetching all database records in an API endpoint using '.all()' or '.find()' without enforcing pagination or a maximum limit ('LIMIT') allows attackers to exhaust server memory and database connections.",
        remediation="Always enforce pagination with a strict maximum page size limit: Model.query.paginate(page=p, per_page=min(size, 50)).",
        remediation_code="""# Safe paginated database query:
page = int(request.args.get('page', 1))
per_page = min(int(request.args.get('per_page', 20)), 100)
items = Item.query.paginate(page=page, per_page=per_page, error_out=False).items""",
        patterns=[
            r"@app\.route\s*\(['\"].*?\)[^\n]*\n(?:[^\n]*\n){1,6}\s*(?:return|items\s*=)\s*[A-Z][a-zA-Z0-9_]*\.query\.all\(\)",
            r"router\.get\s*\(['\"].*?\)[^\n]*\n(?:[^\n]*\n){1,6}\s*(?:return|res\.json)\s*\([^)]*\.find\(\s*\{\s*\}\s*\)",
        ]
    ),
    Rule(
        id="SEC-API-003",
        title="Administrative API Route Missing Role/Permission Check (BFLA)",
        category=OWASPCategory.A01,
        severity=Severity.HIGH,
        cwe="CWE-285",
        languages=["py", "js", "ts"],
        description="Exposing administrative endpoints (e.g. /api/admin/...) without enforcing role-based access control or authorization decorators permits any authenticated user to execute administrative actions.",
        remediation="Apply explicit role verification middleware or decorators (e.g., @admin_required, verify_admin) to all administrative endpoints.",
        remediation_code="""# Safe administrative route protection:
@app.route('/api/admin/users/<id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user_by_admin(id):
    # Authorized administrative action
    pass""",
        patterns=[
            r"@app\.route\s*\(['\"]/(?:api/)?admin/[^'\"]+['\"][^)]*\)[^\n]*\n(?:(?!@admin|@role).)*\ndef\s+[a-zA-Z0-9_]+\(",
        ]
    ),
    Rule(
        id="SEC-API-004",
        title="Excessive Data Exposure: Sensitive Fields Returned in API Response",
        category=OWASPCategory.A02,
        severity=Severity.HIGH,
        cwe="CWE-213",
        languages=["py", "js", "ts"],
        description="Returning raw user objects directly to client responses frequently leaks password hashes, reset tokens, salts, or internal authentication data.",
        remediation="Use dedicated Data Transfer Objects (DTOs) or serialization schemas to explicitly filter out sensitive model attributes before returning data.",
        remediation_code="""# Safe data serialization:
return jsonify({
    "id": user.id,
    "username": user.username,
    "email": user.email
    # Explicitly exclude password_hash, salt, tokens!
})""",
        patterns=[
            r"(?:return\s+jsonify|res\.json)\s*\(\s*\{[^}]*(?:password_hash|passwd_hash|secret_key|auth_token)\s*:",
        ]
    )
]
