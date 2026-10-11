"""OWASP A08:2021 - Software and Data Integrity Failures Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    Rule(
        id="SEC-A08-001",
        title="Insecure Deserialization via Python Pickle / Marshal",
        category=OWASPCategory.A08,
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        languages=["py"],
        description="Deserializing untrusted data with Python's 'pickle' or 'marshal' module allows arbitrary code execution because the pickle format can reconstruct arbitrary Python callables (__reduce__).",
        remediation="Never unpickle data received from untrusted sources. Use safe data interchange formats such as JSON, Protocol Buffers, or MessagePack.",
        remediation_code="""# Safe data deserialization using JSON:
import json

# Safe:
user_data = json.loads(payload)""",
        patterns=[
            r"\b(?:pickle|_pickle|cPickle)\.(?:loads|load)\s*\(",
            r"\bmarshal\.(?:loads|load)\s*\(",
            r"\bshelve\.open\s*\(",
        ]
    ),
    Rule(
        id="SEC-A08-002",
        title="Unsafe YAML Deserialization (yaml.load without SafeLoader)",
        category=OWASPCategory.A08,
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        languages=["py"],
        description="Calling 'yaml.load()' without specifying 'Loader=yaml.SafeLoader' (or using FullLoader/UnsafeLoader) can execute arbitrary code embedded in YAML tags.",
        remediation="Always use 'yaml.safe_load()' or pass 'Loader=yaml.SafeLoader' explicitly.",
        remediation_code="""# Safe YAML loading:
import yaml

# Safe:
data = yaml.safe_load(yaml_string)""",
        patterns=[
            r"yaml\.load\s*\([^,)]+\)",  # yaml.load without Loader arg
            r"yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:Loader|FullLoader|UnsafeLoader)",
        ]
    ),
    Rule(
        id="SEC-A08-003",
        title="Insecure Remote Script Execution (curl | bash / wget | sh)",
        category=OWASPCategory.A08,
        severity=Severity.HIGH,
        cwe="CWE-494",
        languages=["sh", "bash", "dockerfile", "Dockerfile", "py", "js"],
        description="Piping curl or wget directly into a shell interpreter (bash/sh) executes remote code without cryptographic integrity or signature verification, risking supply chain attacks.",
        remediation="Download scripts first, verify their cryptographic checksum / GPG signature, review contents, and execute locally.",
        remediation_code="""# Safe script download & verification:
# 1. Download file:
curl -fsSL https://example.com/install.sh -o install.sh
# 2. Verify SHA256 checksum:
echo "EXPECTED_HASH install.sh" | sha256sum -c -
# 3. Execute:
bash install.sh""",
        patterns=[
            r"curl\s+[^|]+\|\s*(?:ba)?sh\b",
            r"wget\s+[^|]+\|\s*(?:ba)?sh\b",
        ]
    ),
    Rule(
        id="SEC-A08-004",
        title="Insecure PHP Deserialization (unserialize)",
        category=OWASPCategory.A08,
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        languages=["php"],
        description="Passing untrusted input to PHP's 'unserialize()' function triggers magic methods (__wakeup, __destruct) on instantiated objects, frequently leading to Remote Code Execution via property-oriented programming (POP) chains.",
        remediation="Use json_decode() instead of unserialize(). If unserialize() must be used, set 'allowed_classes' to false.",
        remediation_code="""# Safe PHP deserialization:
$data = json_decode($json_string, true);""",
        patterns=[
            r"\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
        ]
    )
]
