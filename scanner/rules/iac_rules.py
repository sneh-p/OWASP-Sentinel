"""Infrastructure-as-Code (IaC), Cloud, and CI/CD Security Rules."""

from ..models import Rule, OWASPCategory, Severity

RULES = [
    # Kubernetes Security Rules
    Rule(
        id="SEC-IAC-001",
        title="Kubernetes Container Configured with Privileged Capabilities",
        category=OWASPCategory.A05,
        severity=Severity.CRITICAL,
        cwe="CWE-250",
        languages=["yaml", "yml"],
        description="Setting 'privileged: true' in securityContext grants container processes full access to the host kernel, devices, and capabilities, enabling trivial container escape.",
        remediation="Never run containers with privileged access. Drop all capabilities and add only explicitly required Linux capabilities (e.g. NET_BIND_SERVICE).",
        remediation_code="""# Secure Kubernetes securityContext:
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  capabilities:
    drop:
      - ALL""",
        patterns=[
            r"privileged\s*:\s*true\b",
            r"allowPrivilegeEscalation\s*:\s*true\b",
        ]
    ),
    Rule(
        id="SEC-IAC-002",
        title="Kubernetes Pod Shares Host Namespace (hostPID / hostNetwork / hostIPC)",
        category=OWASPCategory.A01,
        severity=Severity.HIGH,
        cwe="CWE-250",
        languages=["yaml", "yml"],
        description="Sharing host namespaces (hostPID, hostNetwork, or hostIPC) breaks process isolation, allows inspecting host processes, and permits snooping on other containers on the same node.",
        remediation="Remove hostPID, hostNetwork, and hostIPC flags or set them to false.",
        remediation_code="""# Safe Pod spec:
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false""",
        patterns=[
            r"hostPID\s*:\s*true\b",
            r"hostNetwork\s*:\s*true\b",
            r"hostIPC\s*:\s*true\b",
        ]
    ),
    Rule(
        id="SEC-IAC-003",
        title="Kubernetes Container Missing Resource Limits (DoS Risk)",
        category=OWASPCategory.A04,
        severity=Severity.LOW,
        cwe="CWE-400",
        languages=["yaml", "yml"],
        description="Deploying containers without resource limits (CPU and memory) allows runaway processes or memory leaks to starve other workloads on the Kubernetes node, leading to cluster denial of service.",
        remediation="Specify explicit CPU and memory resource requests and limits for every container.",
        remediation_code="""# Safe resource limits:
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m" """,
        patterns=[
            r"resources:\s*\{\s*\}",
        ]
    ),

    # Terraform & Cloud Infrastructure Security
    Rule(
        id="SEC-IAC-005",
        title="Terraform Security Group Open to World on Sensitive Port",
        category=OWASPCategory.A01,
        severity=Severity.HIGH,
        cwe="CWE-284",
        languages=["tf", "hcl"],
        description="Security group ingress rule allows universal public access ('0.0.0.0/0') to sensitive management or database ports (SSH 22, RDP 3389, PostgreSQL 5432, MongoDB 27017, MySQL 3306).",
        remediation="Restrict security group ingress to specific trusted corporate IP CIDR blocks or VPN gateways.",
        remediation_code="""# Secure Terraform security group rule:
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"] # Private corporate VPC CIDR only!
}""",
        patterns=[
            r"cidr_blocks\s*=\s*\[\s*['\"]0\.0\.0\.0/0['\"]\s*\]",
        ]
    ),
    Rule(
        id="SEC-IAC-006",
        title="Terraform S3 Bucket Configured with Public Read/Write ACL",
        category=OWASPCategory.A01,
        severity=Severity.CRITICAL,
        cwe="CWE-732",
        languages=["tf", "hcl"],
        description="Configuring S3 buckets with 'public-read' or 'public-read-write' exposes stored assets, backups, or confidential data to anyone on the Internet.",
        remediation="Enforce 'private' bucket ACL and enable AWS S3 Public Access Block on all buckets.",
        remediation_code="""# Safe S3 Bucket configuration:
resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket                  = aws_s3_bucket.data_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}""",
        patterns=[
            r"acl\s*=\s*['\"]public-read(?:-write)?['\"]",
        ]
    ),

    # GitHub Actions & CI/CD Pipeline Security
    Rule(
        id="SEC-IAC-008",
        title="GitHub Actions Workflow Injection in Run Script Step",
        category=OWASPCategory.A03,
        severity=Severity.HIGH,
        cwe="CWE-78",
        languages=["yaml", "yml"],
        description="Interpolating untrusted GitHub context expressions (such as issue titles, PR bodies, or commit messages) directly into inline bash 'run' scripts permits remote command injection via pull requests or issues.",
        remediation="Pass untrusted context values through environment variables instead of directly inlining them in script bodies.",
        remediation_code="""# Safe GitHub Actions script execution:
- name: Process Issue Title
  env:
    ISSUE_TITLE: ${{ github.event.issue.title }}
  run: |
    python process.py --title "$ISSUE_TITLE" """,
        patterns=[
            r"run\s*:\s*(?:[^\n]*\n)*?\s*.*?\$\{\{\s*github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body)|comment\.body)",
        ]
    ),
    Rule(
        id="SEC-IAC-009",
        title="Dangerous pull_request_target Trigger in GitHub Actions",
        category=OWASPCategory.A01,
        severity=Severity.HIGH,
        cwe="CWE-284",
        languages=["yaml", "yml"],
        description="Workflows triggered on 'pull_request_target' run with read/write tokens and access to secrets in the target repository context. Checking out untrusted PR head code allows hostile PRs to exfiltrate repository secrets.",
        remediation="Use 'pull_request' instead of 'pull_request_target'. If pull_request_target is necessary for labelling, never check out or execute PR head code.",
        remediation_code="""# Safe pull request event:
on:
  pull_request:
    branches: [ main ]""",
        patterns=[
            r"on:\s*(?:\[[^\]]*pull_request_target|.*pull_request_target:)",
        ]
    )
]
