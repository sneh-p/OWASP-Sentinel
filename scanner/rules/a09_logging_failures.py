"""OWASP A09:2021 - Security Logging and Monitoring Failures Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A09-001",
        title="Logging Sensitive Data (Password, Token, or PII)",
        category=OWASPCategory.A09,
        severity=Severity.HIGH,
        cwe="CWE-532",
        languages=["py", "js", "ts", "java", "go", "php"],
        description="Writing sensitive credentials, tokens, credit card numbers, or passwords to application logs exposes secrets to anyone with log read access, log forwarding pipelines, or third-party log aggregators.",
        remediation="Sanitize or mask sensitive fields before logging. Use structured log filtering or redaction filters.",
        remediation_code="""# Safe sanitized logging:
# Redact sensitive parameters before writing to logs:
sanitized_user = {k: ('***' if k in ['password', 'token', 'cvv', 'secret'] else v) for k, v in data.items()}
logger.info("Authentication attempt for user: %s", sanitized_user.get("username"))""",
        patterns=[
            r"(?:logger|logging|console)\.(?:info|debug|warn|error|log)\s*\([^)]*(?:password|passwd|api_key|token|jwt|secret|credit_card|cvv)",
            r"print\s*\([^)]*(?:password|token|api_key|secret)\s*[:=]",
        ]
    ),
    Rule(
        id="SEC-A09-002",
        title="Silent Exception Swallowing / Missing Error Logging",
        category=OWASPCategory.A09,
        severity=Severity.LOW,
        cwe="CWE-391",
        languages=["py", "js", "ts", "java"],
        description="Catching exceptions and silently ignoring them with 'pass' or empty catch blocks blinds security monitoring, conceals active attacks, and hides software malfunctions.",
        remediation="Always log caught exceptions with appropriate log levels and diagnostic context before handling.",
        remediation_code="""# Safe exception handling with logging:
try:
    process_transaction()
except TransactionError as e:
    logger.exception("Transaction processing failed: %s", e)
    notify_admin_or_revert()""",
        patterns=[
            r"except(?:\s+[A-Za-z0-9_]+)?:\s*\n\s+pass\b",
            r"catch\s*\([^)]*\)\s*\{\s*\}",
        ]
    )
]
