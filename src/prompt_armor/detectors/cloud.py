"""
Cloud infrastructure identifier detector — universal, no config needed.

Covers AWS, GCP, Azure, Kubernetes, Docker registries,
internal hostnames, cloud console URLs, resource identifiers.

Company-specific overrides loaded from prompt_armor.yaml.
"""

from __future__ import annotations

import re

from ..models import DetectionCategory, DetectionFinding, DetectionResult, Severity

_PATTERNS: list[tuple[str, str, Severity, str]] = [

    # ── AWS Resource Identifiers ──────────────────────────────────────
    (r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{0,12}:[^\s\"',]+", "AWS ARN", Severity.HIGH, "AWS_ARN"),
    (r"\bi-[0-9a-f]{8,17}\b", "AWS EC2 Instance ID", Severity.MEDIUM, "AWS_EC2_INSTANCE"),
    (r"\bami-[0-9a-f]{8,17}\b", "AWS AMI ID", Severity.LOW, "AWS_AMI"),
    (r"\bsg-[0-9a-f]{8,17}\b", "AWS Security Group ID", Severity.MEDIUM, "AWS_SG"),
    (r"\bvpc-[0-9a-f]{8,17}\b", "AWS VPC ID", Severity.MEDIUM, "AWS_VPC"),
    (r"\bsubnet-[0-9a-f]{8,17}\b", "AWS Subnet ID", Severity.LOW, "AWS_SUBNET"),
    (r"\bvol-[0-9a-f]{8,17}\b", "AWS EBS Volume ID", Severity.LOW, "AWS_EBS_VOL"),
    (r"\bsnap-[0-9a-f]{8,17}\b", "AWS Snapshot ID", Severity.LOW, "AWS_SNAPSHOT"),
    (r"\brtb-[0-9a-f]{8,17}\b", "AWS Route Table ID", Severity.LOW, "AWS_RTB"),
    (r"\bigw-[0-9a-f]{8,17}\b", "AWS Internet Gateway ID", Severity.LOW, "AWS_IGW"),
    (r"\beks:[a-z0-9\-]+:[a-z0-9\-]+:cluster/[a-zA-Z0-9\-]+", "AWS EKS Cluster ARN", Severity.HIGH, "AWS_EKS"),
    (r"\b[a-z0-9\-]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com\b", "AWS API Gateway URL", Severity.MEDIUM, "AWS_APIGW"),
    (r"\b[a-z0-9\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com\b", "AWS S3 Bucket URL", Severity.MEDIUM, "AWS_S3_URL"),
    (r"\b[a-z0-9\-]+\.rds\.[a-z0-9\-]+\.amazonaws\.com\b", "AWS RDS Endpoint", Severity.HIGH, "AWS_RDS_ENDPOINT"),
    (r"\b[a-z0-9\-]+\.cache\.[a-z0-9\-]+\.amazonaws\.com\b", "AWS ElastiCache Endpoint", Severity.HIGH, "AWS_ELASTICACHE"),
    (r"\b\d{12}\.dkr\.ecr\.[a-z0-9\-]+\.amazonaws\.com\b", "AWS ECR Registry URL", Severity.HIGH, "AWS_ECR"),
    (r"console\.aws\.amazon\.com/[a-z0-9\-/]+\?[^\s\"']+", "AWS Console URL with params", Severity.MEDIUM, "AWS_CONSOLE_URL"),

    # ── GCP Resource Identifiers ──────────────────────────────────────
    (r"projects/[a-z][a-z0-9\-]{4,28}[a-z0-9]/(?:zones|regions|global)/[^\s\"',]+", "GCP Resource Path", Severity.HIGH, "GCP_RESOURCE"),
    (r"\b[a-z0-9\-]+\.googleapis\.com\b", "GCP API Endpoint", Severity.MEDIUM, "GCP_API_ENDPOINT"),
    (r"storage\.googleapis\.com/[a-z0-9\-_\.]+", "GCP Cloud Storage URL", Severity.MEDIUM, "GCP_GCS_URL"),
    (r"\b[a-z0-9\-]+\.cloudfunctions\.net\b", "GCP Cloud Functions URL", Severity.MEDIUM, "GCP_CF_URL"),
    (r"\b[a-z0-9\-]+\.run\.app\b", "GCP Cloud Run URL", Severity.MEDIUM, "GCP_RUN_URL"),
    (r"gcr\.io/[a-z0-9\-]+/[a-zA-Z0-9\-_/]+", "GCP Container Registry", Severity.MEDIUM, "GCP_GCR"),
    (r"pkg\.dev/[a-z0-9\-]+/[a-zA-Z0-9\-_/]+", "GCP Artifact Registry", Severity.MEDIUM, "GCP_AR"),

    # ── Azure Resource Identifiers ────────────────────────────────────
    (r"/subscriptions/[0-9a-f\-]{36}/resourceGroups/[^\s\"',/]+", "Azure Resource Group Path", Severity.HIGH, "AZURE_RG"),
    (r"\b[a-z0-9\-]+\.blob\.core\.windows\.net\b", "Azure Blob Storage URL", Severity.MEDIUM, "AZURE_BLOB"),
    (r"\b[a-z0-9\-]+\.database\.windows\.net\b", "Azure SQL Server Endpoint", Severity.HIGH, "AZURE_SQL"),
    (r"\b[a-z0-9\-]+\.azurewebsites\.net\b", "Azure App Service URL", Severity.MEDIUM, "AZURE_WEBAPP"),
    (r"\b[a-z0-9\-]+\.azure-api\.net\b", "Azure API Management URL", Severity.MEDIUM, "AZURE_APIM"),
    (r"\b[a-z0-9\-]+\.azurecr\.io\b", "Azure Container Registry", Severity.MEDIUM, "AZURE_ACR"),
    (r"\b[a-z0-9\-]+\.servicebus\.windows\.net\b", "Azure Service Bus", Severity.MEDIUM, "AZURE_SB"),
    (r"\b[a-z0-9\-]+\.vault\.azure\.net\b", "Azure Key Vault URL", Severity.HIGH, "AZURE_KEYVAULT"),

    # ── Kubernetes ───────────────────────────────────────────────────
    (r"https?://[a-z0-9\-\.]+:\d{4,5}(?=/api/v[12])", "Kubernetes API Server URL", Severity.HIGH, "K8S_API_SERVER"),
    (r"\bkube(?:config|ctl)\b.*(?:--server|--token|--certificate)", "Kubectl with credentials", Severity.CRITICAL, "KUBECTL_CRED"),
    (r"cluster\.local(?:/[^\s\"']+)?", "Kubernetes cluster.local reference", Severity.LOW, "K8S_CLUSTER_LOCAL"),

    # ── Docker / Container Registries ────────────────────────────────
    (r"[a-z0-9\-]+\.azurecr\.io/[a-zA-Z0-9\-_/]+:[a-zA-Z0-9\-_\.]+", "Azure ACR Image", Severity.MEDIUM, "ACR_IMAGE"),
    (r"\d{12}\.dkr\.ecr\.[a-z0-9\-]+\.amazonaws\.com/[a-zA-Z0-9\-_/]+", "ECR Image Reference", Severity.HIGH, "ECR_IMAGE"),

    # ── Internal Hostnames (generic patterns) ─────────────────────────
    (r"\b(?:prod|staging|stg|dev|internal|corp|infra)[\-\.][\w\-\.]+\.(?:internal|local|corp|lan|intranet)\b", "Internal hostname", Severity.HIGH, "INTERNAL_HOSTNAME"),
    (r"\b(?:db|database|mysql|postgres|redis|mongo|elastic|kafka|rabbit)[\-\.][\w\-]+(?:\.internal|\.local|\.corp)?\b", "Internal database hostname", Severity.HIGH, "DB_HOSTNAME"),
    (r"\b(?:jenkins|gitlab|github|bitbucket|jira|confluence|sonar|nexus|artifactory)[\-\.][\w\-]+\.(?:internal|local|corp)\b", "Internal tool hostname", Severity.MEDIUM, "INTERNAL_TOOL"),

    # ── Cloud Provider Console URLs (with account context) ────────────
    (r"https://console\.cloud\.google\.com/[^\s\"']*project=[a-z0-9\-]+", "GCP Console URL with project", Severity.MEDIUM, "GCP_CONSOLE_URL"),
    (r"https://portal\.azure\.com/[^\s\"']*subscriptions/[0-9a-f\-]{36}", "Azure Portal URL with subscription", Severity.MEDIUM, "AZURE_PORTAL_URL"),

    # ── Terraform State / Secrets ─────────────────────────────────────
    (r'"sensitive":\s*true.*"value":\s*"[^"]{8,}"', "Terraform sensitive output value", Severity.CRITICAL, "TF_SENSITIVE"),
    (r'terraform\.tfstate', "Terraform state file reference", Severity.HIGH, "TF_STATE_FILE"),
]


class CloudDetector:
    def __init__(self, extra_patterns: list[tuple[str, str]] | None = None) -> None:
        """
        extra_patterns: list of (regex, label) tuples from company config.
        Loaded by CompanyDetector from prompt_armor.yaml.
        """
        self._compiled = [
            (re.compile(p, re.IGNORECASE | re.MULTILINE), desc, sev, label)
            for p, desc, sev, label in _PATTERNS
        ]

        if extra_patterns:
            for pattern_str, label in extra_patterns:
                try:
                    self._compiled.append((
                        re.compile(pattern_str, re.IGNORECASE),
                        f"Company cloud resource: {label}",
                        Severity.HIGH,
                        label,
                    ))
                except re.error:
                    pass  # Skip invalid patterns

    def scan(self, text: str) -> DetectionResult:
        findings: list[DetectionFinding] = []

        for pattern, desc, severity, label in self._compiled:
            m = pattern.search(text)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.PII_INPUT,
                    severity=severity,
                    confidence=0.9,
                    description=desc,
                    matched_pattern=f"[{label}: {m.group()[:60]}]",
                    position=m.start(),
                ))

        blocked = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        return DetectionResult(blocked=blocked, findings=findings)
