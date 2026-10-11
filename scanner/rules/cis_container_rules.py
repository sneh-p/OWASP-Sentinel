"""CIS Benchmarks: Docker, Kubernetes, and Cloud Infrastructure-as-Code Security Rules."""

from ..models import Rule, SecurityCategory, Severity

RULES = [
    Rule(
        id="CIS-DOCKER-001",
        title="Container Process Running as Root User (CIS Docker 4.1)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.HIGH,
        cwe="CWE-250",
        languages=["dockerfile"],
        description="Running containers as the 'root' user allows attackers who breach the application inside the container to have root privileges on the container runtime, significantly easing host compromise.",
        remediation="Create a dedicated non-root user and group, and switch to it using the 'USER' directive before running the application process.",
        remediation_code="""# Safe Dockerfile configuration:
RUN groupadd -r appuser && useradd -r -g appuser -d /home/appuser -s /sbin/nologin -c "Docker image user" appuser
USER appuser""",
        patterns=[
            r"^\s*USER\s+root\b",
        ],
        standard="CIS Docker Benchmark",
        frameworks=["CIS Benchmarks", "Container Hardening"],
    ),
    Rule(
        id="CIS-DOCKER-002",
        title="Base Image Using Unpinned or Mutable ':latest' Tag (CIS Docker 4.2)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.MEDIUM,
        cwe="CWE-1357",
        languages=["dockerfile"],
        description="Using ':latest' or untagged base images leads to non-deterministic builds, unpredictable vulnerability introductions, and potential supply-chain poisoning.",
        remediation="Pin base images to an exact immutable version tag or SHA-256 digest hash.",
        remediation_code="""# Pinned immutable base image:
FROM python:3.11.8-slim-bookworm@sha256:d8692...""",
        patterns=[
            r"^\s*FROM\s+[\w\.\-\/]+:latest\b",
            r"^\s*FROM\s+[a-zA-Z0-9_\-\/]+(?:\s+AS\s+\w+)?$",
        ],
        standard="CIS Docker Benchmark",
        frameworks=["CIS Benchmarks", "OpenSSF / SLSA"],
    ),
    Rule(
        id="CIS-DOCKER-003",
        title="Missing HEALTHCHECK Instruction in Container Image (CIS Docker 4.6)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.LOW,
        cwe="CWE-754",
        languages=["dockerfile"],
        description="Without a HEALTHCHECK instruction, the container orchestrator cannot verify if the application inside has crashed, deadlocked, or entered a zombie state.",
        remediation="Add a HEALTHCHECK instruction that queries an internal endpoint or status check script.",
        remediation_code="""# Add healthcheck to Dockerfile:
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\
  CMD curl -f http://localhost:8080/health || exit 1""",
        patterns=[
            r"^\s*HEALTHCHECK\s+NONE\b",
        ],
        standard="CIS Docker Benchmark",
        frameworks=["CIS Benchmarks"],
    ),
    Rule(
        id="CIS-DOCKER-004",
        title="Insecure Pipe-to-Shell Script Execution (curl | bash)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.HIGH,
        cwe="CWE-494",
        languages=["dockerfile", "sh", "bash", "yaml", "yml"],
        description="Piping remote scripts directly to a shell ('curl ... | bash' or 'wget ... | sh') executes unverified third-party code without signature verification or checksum validation.",
        remediation="Download the installation package or script, verify its cryptographic hash or PGP signature, and only then execute it.",
        remediation_code="""# Safe script verification:
curl -sSL https://example.com/install.sh -o install.sh
echo "expected_sha256_hash  install.sh" | sha256sum -c -
bash install.sh""",
        patterns=[
            r"curl\s+[^\n\|]*\|\s*(?:bash|sh|zsh)\b",
            r"wget\s+[^\n\|]*\|\s*(?:bash|sh|zsh)\b",
        ],
        standard="CIS Docker Benchmark",
        frameworks=["CIS Benchmarks", "OpenSSF / SLSA"],
    ),
    Rule(
        id="CIS-DOCKER-005",
        title="Docker Daemon Socket Exposed / Mounted Inside Container (CIS Docker 5.31)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.CRITICAL,
        cwe="CWE-250",
        languages=["yaml", "yml"],
        description="Mounting '/var/run/docker.sock' gives processes inside the container full root control over the host Docker daemon, allowing full host takeover.",
        remediation="Never mount the Docker daemon socket inside application containers. Use rootless container tools (e.g. Kaniko, Buildah) or remote CI agents.",
        remediation_code="""# Safe volume mounts in docker-compose.yml:
volumes:
  - ./app_data:/var/app/data:ro  # Read-only non-socket mount""",
        patterns=[
            r"\/var\/run\/docker\.sock",
        ],
        standard="CIS Docker Benchmark",
        frameworks=["CIS Benchmarks", "Container Hardening"],
    ),
    Rule(
        id="CIS-DOCKER-006",
        title="Insecure ADD Instruction Used for Local Files (CIS Docker 4.9)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.LOW,
        cwe="CWE-494",
        languages=["dockerfile"],
        description="The Docker ADD instruction performs automatic tar extraction and remote URL fetching, leading to unpredictable archive bomb or SSRF risks. COPY is strictly safer for local files.",
        remediation="Use 'COPY' instead of 'ADD' unless automatic tar extraction from a local archive is strictly necessary.",
        remediation_code="""# Safe file copy:
COPY src/ /app/src/""",
        patterns=[
            r"^\s*ADD\s+(?!https?:\/\/|ftp:\/\/)\S+\s+\S+",
        ],
        standard="CIS Docker Benchmark",
        frameworks=["CIS Benchmarks"],
    ),
    Rule(
        id="CIS-K8S-001",
        title="Kubernetes Container Missing readOnlyRootFilesystem (CIS K8s 5.2.5)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.MEDIUM,
        cwe="CWE-732",
        languages=["yaml", "yml"],
        description="Allowing writable root filesystems in containers enables attackers who exploit an application vulnerability to write malicious binaries, modify scripts, or persist malware.",
        remediation="Set 'readOnlyRootFilesystem: true' in securityContext and mount dedicated temporary directories (emptyDir) for scratch files.",
        remediation_code="""# Safe read-only filesystem:
securityContext:
  readOnlyRootFilesystem: true""",
        patterns=[
            r"readOnlyRootFilesystem\s*:\s*false\b",
        ],
        standard="CIS Kubernetes Benchmark",
        frameworks=["CIS Benchmarks", "Container Hardening"],
    ),
    Rule(
        id="CIS-K8S-002",
        title="Kubernetes Container Requests Dangerous SYS_ADMIN or NET_ADMIN Capability",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.CRITICAL,
        cwe="CWE-250",
        languages=["yaml", "yml"],
        description="Granting CAP_SYS_ADMIN or CAP_NET_ADMIN provides almost identical capabilities to full root on the host, including mounting filesystems and overriding kernel limits.",
        remediation="Remove SYS_ADMIN and NET_ADMIN. Run containers with non-privileged capabilities.",
        remediation_code="""# Safe capabilities drop:
capabilities:
  drop:
    - ALL""",
        patterns=[
            r"capabilities:\s*(?:[^\n]*\n)*?\s*add:\s*(?:[^\n]*\n)*?\s*-\s*[\"']?(?:SYS_ADMIN|NET_ADMIN)[\"']?",
        ],
        standard="CIS Kubernetes Benchmark",
        frameworks=["CIS Benchmarks", "Container Hardening"],
    ),
    Rule(
        id="CIS-CLOUD-001",
        title="Terraform AWS EBS Volume Unencrypted at Rest (CIS AWS 2.2.1)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.HIGH,
        cwe="CWE-311",
        languages=["tf", "hcl"],
        description="Storing data on unencrypted Elastic Block Store (EBS) volumes exposes block-level data in case of disk compromise or snapshot mishandling.",
        remediation="Set 'encrypted = true' and specify an authorized AWS KMS customer-managed key.",
        remediation_code="""# Encrypted EBS volume in Terraform:
resource "aws_ebs_volume" "secure_volume" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
  kms_key_id        = aws_kms_key.app_key.arn
}""",
        patterns=[
            r"encrypted\s*=\s*false\b",
        ],
        standard="CIS AWS Foundations Benchmark",
        frameworks=["CIS Benchmarks", "Cloud Security"],
    ),
    Rule(
        id="CIS-CLOUD-002",
        title="Terraform AWS RDS Database Publicly Accessible (CIS AWS 2.3.1)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.CRITICAL,
        cwe="CWE-284",
        languages=["tf", "hcl"],
        description="Setting 'publicly_accessible = true' on an RDS database exposes its listening port directly to the public internet, inviting automated credential brute-force.",
        remediation="Set 'publicly_accessible = false' and place the RDS database within private VPC subnets accessible only by internal application instances.",
        remediation_code="""# Private RDS instance in Terraform:
resource "aws_db_instance" "db" {
  allocated_storage   = 20
  engine              = "postgres"
  publicly_accessible = false
}""",
        patterns=[
            r"publicly_accessible\s*=\s*true\b",
        ],
        standard="CIS AWS Foundations Benchmark",
        frameworks=["CIS Benchmarks", "Cloud Security"],
    ),
    Rule(
        id="CIS-CLOUD-003",
        title="Overly Permissive IAM Policy with Action '*' and Resource '*' (CIS AWS 1.16)",
        category=SecurityCategory.CIS_CONTAINER,
        severity=Severity.CRITICAL,
        cwe="CWE-732",
        languages=["tf", "hcl", "json"],
        description="Granting 'Action: *' combined with 'Resource: *' gives administrative superuser control over all cloud services in the account, violating the principle of least privilege.",
        remediation="Grant strictly scoped actions on specific designated resource ARNs.",
        remediation_code="""# Least privilege IAM policy:
Statement = [
  {
    Action   = ["s3:GetObject"]
    Effect   = "Allow"
    Resource = "arn:aws:s3:::app-data-bucket/*"
  }
]""",
        patterns=[
            r"\"Action\"\s*:\s*\"[*]\"\s*,\s*\"Resource\"\s*:\s*\"[*]\"",
            r"Action\s*=\s*\[?\s*['\"]\s*[*]\s*['\"]\s*\]?[\s\S]{1,60}Resource\s*=\s*\[?\s*['\"]\s*[*]\s*['\"]\s*\]?",
        ],
        standard="CIS AWS Foundations Benchmark",
        frameworks=["CIS Benchmarks", "Cloud Security"],
    ),
]
