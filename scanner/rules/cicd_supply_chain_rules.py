"""CI/CD Pipeline and OpenSSF / SLSA Supply Chain Security Rules."""

from ..models import Rule, SecurityCategory, Severity

RULES = [
    Rule(
        id="SLSA-CI-001",
        title="Unpinned Third-Party GitHub Action (SLSA Build Level 3)",
        category=SecurityCategory.SUPPLY_CHAIN,
        severity=Severity.MEDIUM,
        cwe="CWE-1357",
        languages=["yaml", "yml"],
        description="Referencing GitHub Actions using mutable tags (such as @v1, @main, or @master) allows an attacker who compromises the upstream repository or tag to inject malicious steps into your build pipeline.",
        remediation="Pin third-party GitHub Actions to a full 40-character commit SHA digest, and use automated dependency bots (like Renovate or Dependabot) to manage updates.",
        remediation_code="""# Safe pinned GitHub Action:
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1""",
        patterns=[
            r"uses:\s*actions\/[a-zA-Z0-9_\-]+@(?:v[0-9]+(?:\.[0-9]+)*|main|master)\b",
            r"uses:\s*(?!docker:\/\/)(?!actions\/)[a-zA-Z0-9_\-\/]+@(?:v[0-9]+|main|master)\b",
        ],
        standard="OpenSSF / SLSA",
        frameworks=["OpenSSF / SLSA", "Supply Chain Security"],
    ),
    Rule(
        id="SLSA-CI-002",
        title="Excessive Pipeline Permissions - write-all Granted",
        category=SecurityCategory.SUPPLY_CHAIN,
        severity=Severity.HIGH,
        cwe="CWE-250",
        languages=["yaml", "yml"],
        description="Configuring 'permissions: write-all' gives the GitHub Actions GITHUB_TOKEN write access to contents, packages, issues, and security events, allowing compromised dependencies to tamper with git branches.",
        remediation="Define minimal granular permissions for the job (e.g. 'contents: read').",
        remediation_code="""# Safe granular permissions:
permissions:
  contents: read
  issues: write""",
        patterns=[
            r"permissions:\s*write-all\b",
        ],
        standard="OpenSSF / SLSA",
        frameworks=["OpenSSF / SLSA", "Supply Chain Security"],
    ),
    Rule(
        id="SLSA-CI-003",
        title="Potential Pipeline Secret Exposure in Build Echo / Print Step",
        category=SecurityCategory.SUPPLY_CHAIN,
        severity=Severity.HIGH,
        cwe="CWE-532",
        languages=["yaml", "yml", "sh", "bash"],
        description="Echoing or logging environment variables containing secrets in pipeline steps can leak sensitive authentication keys directly into public build logs.",
        remediation="Never print secrets in CI logs. Use encrypted secrets masking or designated secret integration actions.",
        remediation_code="""# Safe secret usage without logging:
- name: Deploy
  env:
    API_KEY: ${{ secrets.PROD_API_KEY }}
  run: ./deploy.sh""",
        patterns=[
            r"echo\s+['\"].*\$\{\{\s*secrets\.[A-Za-z0-9_]+",
            r"console\.log\(.*process\.env\.[A-Za-z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN)",
        ],
        standard="OpenSSF / SLSA",
        frameworks=["OpenSSF / SLSA", "Secrets & Key Protection"],
    ),
    Rule(
        id="SLSA-CI-004",
        title="GitLab CI Unverified Script Execution in Pipeline",
        category=SecurityCategory.SUPPLY_CHAIN,
        severity=Severity.HIGH,
        cwe="CWE-494",
        languages=["yaml", "yml"],
        description="Downloading and executing unverified scripts in GitLab CI jobs ('before_script' / 'script') risks executing compromised payloads.",
        remediation="Check the script into repository source control or verify its SHA-256 hash prior to execution.",
        remediation_code="""# Safe verified execution:
before_script:
  - sha256sum -c script.sha256
  - ./verified-script.sh""",
        patterns=[
            r"script:\s*(?:[^\n]*\n)*?\s*-\s*curl\s+[^\n\|]*\|\s*(?:bash|sh)\b",
        ],
        standard="OpenSSF / SLSA",
        frameworks=["OpenSSF / SLSA", "Supply Chain Security"],
    ),
]
