"""OWASP A02:2021 - Cryptographic Failures Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A02-001",
        title="Hardcoded Secret, Private Key, or API Token in Source Code",
        category=OWASPCategory.A02,
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        languages=["py", "js", "ts", "json", "yml", "yaml", "env", "go", "java"],
        description="Credentials, private keys, API secrets, or database passwords embedded directly in code can be extracted through version control, logs, or artifact leaks, giving attackers unauthorized access.",
        remediation="Store secrets in environment variables or a dedicated secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Never commit secrets into source code.",
        remediation_code="""# Safe secret retrieval:
import os

SECRET_KEY = os.environ.get("APP_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("APP_SECRET_KEY environment variable is missing")""",
        patterns=[
            r"(?i)(?:api_key|apikey|secret_key|private_key|auth_token|jwt_secret|aws_secret_access_key)\s*[:=]\s*['\"][A-Za-z0-9+/=_\-\.]{16,}['\"]",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            r"(?i)AKIA[0-9A-Z]{16}",
            r"(?i)ghp_[0-9a-zA-Z]{36}",
            r"(?i)stripe_(?:live|test)_[0-9a-zA-Z]{24,}",
            r"(?i)password\s*=\s*['\"][^'\"]{6,}['\"]",
        ]
    ),
    Rule(
        id="SEC-A02-002",
        title="Use of Weak Cryptographic Hash Function (MD5 / SHA1)",
        category=OWASPCategory.A02,
        severity=Severity.HIGH,
        cwe="CWE-328",
        languages=["py", "js", "ts", "php", "java", "go"],
        description="MD5 and SHA-1 suffer from known collision and pre-image attacks and must not be used for password hashing, digital signatures, or integrity verification.",
        remediation="Use secure collision-resistant hash algorithms such as SHA-256 / SHA-512, or adaptive password hashing algorithms like Argon2id, bcrypt, or PBKDF2 for passwords.",
        remediation_code="""# Safe password hashing:
import bcrypt

salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

# Safe data integrity hashing:
import hashlib
digest = hashlib.sha256(data).hexdigest()""",
        patterns=[
            r"hashlib\.(?:md5|sha1)\s*\(",
            r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)",
            r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)['\"]\s*\)",
            r"(?:md5|sha1)\s*\(\s*\$[^)]+\)",
        ]
    ),
    Rule(
        id="SEC-A02-003",
        title="Use of Insecure Cipher or Mode (DES / RC4 / ECB Mode)",
        category=OWASPCategory.A02,
        severity=Severity.HIGH,
        cwe="CWE-327",
        languages=["py", "js", "ts", "java", "go", "php"],
        description="Legacy ciphers like DES, TripleDES, RC4, or AES in ECB mode are cryptographically broken and vulnerable to pattern analysis, padding oracle, and brute force attacks.",
        remediation="Use AES with authenticated encryption modes like GCM (Galois/Counter Mode) or ChaCha20-Poly1305 with random unique IVs/nonces.",
        remediation_code="""# Safe AES-GCM encryption:
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)""",
        patterns=[
            r"(?i)AES\.MODE_ECB\b",
            r"(?i)(?:DES|TripleDES|Blowfish|ARC4|RC4)\.new\s*\(",
            r"Cipher\.getInstance\s*\(\s*['\"][^'\"]*(?:ECB|DES|RC4)[^'\"]*['\"]\s*\)",
            r"crypto\.createCipher(?:iv)?\s*\(\s*['\"](?:des|rc4|blowfish)[^'\"]*['\"]",
        ]
    ),
    Rule(
        id="SEC-A02-004",
        title="Disabled SSL/TLS Certificate Validation",
        category=OWASPCategory.A02,
        severity=Severity.CRITICAL,
        cwe="CWE-295",
        languages=["py", "js", "ts", "go", "java"],
        description="Disabling TLS certificate verification allows attackers to intercept, read, or modify encrypted traffic using Machine-in-the-Middle (MitM) attacks.",
        remediation="Enable certificate verification for all HTTPS requests. Ensure valid CA trust stores are configured.",
        remediation_code="""# Safe HTTPS request with verification:
import requests

response = requests.get("https://api.example.com/data", verify=True, timeout=10)""",
        patterns=[
            r"requests\.(?:get|post|put|delete|patch|request)\s*\([^)]*verify\s*=\s*False",
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?",
            r"rejectUnauthorized\s*:\s*false",
            r"InsecureSkipVerify\s*:\s*true",
            r"ssl\.CERT_NONE\b",
            r"urllib3\.disable_warnings\s*\(",
        ]
    ),
    Rule(
        id="SEC-A02-005",
        title="Use of Cryptographically Weak Pseudorandom Number Generator",
        category=OWASPCategory.A02,
        severity=Severity.MEDIUM,
        cwe="CWE-338",
        languages=["py", "js", "ts", "java", "go"],
        description="Standard PRNGs like Python's 'random' or JavaScript's 'Math.random()' use predictable algorithms (Mersenne Twister) and must not be used for generating security tokens, session IDs, or password reset tokens.",
        remediation="Use a cryptographically secure random number generator such as Python's 'secrets' module or 'os.urandom()', or Web Crypto API 'crypto.getRandomValues()'.",
        remediation_code="""# Safe cryptographic token generation:
import secrets

secure_token = secrets.token_urlsafe(32)""",
        patterns=[
            r"(?i)(?:token|password|secret|auth|nonce|session_id)\s*=\s*.*(?:random\.random|random\.randint|random\.choice|Math\.random)",
            r"(?i)def\s+generate_(?:token|secret|password|key)\b[^\n]*\n[^:\n]*random\.(?:random|choice|randint)",
        ]
    ),
    Rule(
        id="SEC-A02-006",
        title="Hardcoded Credentials or Private Keys in Dockerfile",
        category=OWASPCategory.A02,
        severity=Severity.CRITICAL,
        cwe="CWE-798",
        languages=["dockerfile", "Dockerfile"],
        description="Defining API tokens, private keys, or passwords inside Dockerfile ENV or ARG directives bakes confidential secrets into public image layers.",
        remediation="Use Docker BuildKit secrets mount (--mount=type=secret) or runtime environment injection via Kubernetes Secrets / Vault.",
        remediation_code="""# Safe secret mounting in Dockerfile:
# syntax=docker/dockerfile:1.2
RUN --mount=type=secret,id=api_key cat /run/secrets/api_key""",
        patterns=[
            r"(?i)^ENV\s+[A-Za-z0-9_]*(?:PASSWORD|PASS|SECRET|API_KEY|TOKEN)\s*=\s*['\"][^'\"]+['\"]",
            r"(?i)^ARG\s+[A-Za-z0-9_]*(?:PASSWORD|PASS|SECRET|API_KEY|TOKEN)\s*=\s*['\"][^'\"]+['\"]",
        ]
    )
]
