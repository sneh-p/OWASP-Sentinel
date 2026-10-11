"""OWASP A10:2021 - Server-Side Request Forgery (SSRF) Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A10-001",
        title="Server-Side Request Forgery (SSRF) via Unvalidated URL Request",
        category=OWASPCategory.A10,
        severity=Severity.HIGH,
        cwe="CWE-918",
        languages=["py", "js", "ts", "php", "java", "go"],
        description="Allowing user input to specify a destination URL for a server-side HTTP request enables attackers to send requests to internal network services, cloud metadata services (e.g. 169.254.169.254), or loopback addresses.",
        remediation="Validate URLs against a strict domain whitelist, block private/loopback IP addresses (RFC 1918, 127.0.0.0/8, 169.254.0.0/16), disable HTTP redirects, and resolve DNS before connecting.",
        remediation_code="""# Safe URL fetching with IP allowlist:
import ipaddress
import socket
from urllib.parse import urlparse
import requests

def safe_fetch(user_url):
    parsed = urlparse(user_url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Invalid scheme")
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise PermissionError("Access to internal/private network is forbidden")
    return requests.get(user_url, allow_redirects=False, timeout=5)""",
        patterns=[
            r"requests\.(?:get|post|put|delete|head)\s*\(\s*(?:request\.(?:args|form|values|json)\[|req\.(?:query|body|params)\.|target_url|user_url|url_param)",
            r"urllib\.request\.urlopen\s*\(\s*(?:request\.|req\.|target_url|user_url)",
            r"axios\.(?:get|post|request)\s*\(\s*req\.(?:query|body|params)\.",
            r"fetch\s*\(\s*req\.(?:query|body|params)\.",
            r"file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)\[",
        ]
    ),
    Rule(
        id="SEC-A10-002",
        title="Potential SSRF to Cloud Metadata Service (169.254.169.254)",
        category=OWASPCategory.A10,
        severity=Severity.CRITICAL,
        cwe="CWE-918",
        languages=["py", "js", "ts", "sh", "yaml", "yml"],
        description="Referencing cloud metadata endpoint 169.254.169.254 in unconstrained request flows risks leaking IAM credentials, kubelet tokens, or instance identity documents.",
        remediation="Never allow external or untrusted requests to target 169.254.169.254. Enable IMDSv2 (requiring token headers) in AWS.",
        remediation_code="""# Block metadata endpoint:
if "169.254.169.254" in url or "metadata.google.internal" in url:
    raise SecurityException("Cloud metadata access blocked")""",
        patterns=[
            r"169\.254\.169\.254",
            r"metadata\.google\.internal",
        ]
    )
]
