"""
Secrets & credentials detector — universal, no config needed.

Covers:
  AWS, GCP, Azure, GitHub, Slack, Stripe, Twilio, SendGrid,
  NPM, PyPI, Docker, Terraform Cloud, HashiCorp Vault,
  Hugging Face, Replicate, OpenRouter, Pinecone, Supabase,
  Vercel, Cloudflare, Linear, Notion, Figma,
  Private keys, Connection strings, JWT, Webhook tokens
"""

from __future__ import annotations

import re

from ..models import DetectionCategory, DetectionFinding, DetectionResult, Severity


_PATTERNS: list[tuple[str, str, Severity, str]] = [
    # ── AWS ──────────────────────────────────────────────────────────
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key ID", Severity.CRITICAL, "AWS_ACCESS_KEY"),
    (r"\bASIA[0-9A-Z]{16}\b", "AWS Temporary Access Key", Severity.CRITICAL, "AWS_TEMP_KEY"),
    (r"aws[_\-\s]?(secret|secret_key|secret_access_key)[_\-\s]*[=:][_\-\s]*[A-Za-z0-9/+]{40}\b", "AWS Secret Access Key", Severity.CRITICAL, "AWS_SECRET_KEY"),
    (r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s\"']+", "AWS ARN with account ID", Severity.HIGH, "AWS_ARN"),
    (r"\b\d{12}\b(?=.*aws|.*arn|.*account)", "AWS Account ID in context", Severity.HIGH, "AWS_ACCOUNT_ID"),

    # ── GCP ──────────────────────────────────────────────────────────
    (r"\bAIza[0-9A-Za-z\-_]{35}\b", "GCP API Key", Severity.CRITICAL, "GCP_API_KEY"),
    (r"[\w\-\.]+@[\w\-]+\.iam\.gserviceaccount\.com", "GCP Service Account Email", Severity.CRITICAL, "GCP_SERVICE_ACCOUNT"),
    (r'"type"\s*:\s*"service_account"', "GCP Service Account JSON", Severity.CRITICAL, "GCP_SA_JSON"),
    (r'"private_key_id"\s*:\s*"[a-f0-9]{40}"', "GCP Private Key ID", Severity.CRITICAL, "GCP_PRIVATE_KEY_ID"),
    (r"projects/[a-z][a-z0-9\-]{4,28}[a-z0-9]/", "GCP Project Resource Path", Severity.MEDIUM, "GCP_PROJECT_PATH"),

    # ── Azure ─────────────────────────────────────────────────────────
    (r"/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "Azure Subscription ID in path", Severity.HIGH, "AZURE_SUB_ID"),
    (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=.*tenant|.*client|.*subscription)", "Azure UUID (tenant/client/subscription)", Severity.HIGH, "AZURE_UUID"),
    (r"DefaultEndpointsProtocol=https;AccountName=[\w]+;AccountKey=[A-Za-z0-9+/=]{88}", "Azure Storage Connection String", Severity.CRITICAL, "AZURE_STORAGE_CONN"),
    (r"AccountKey=[A-Za-z0-9+/]{86}==", "Azure Storage Account Key", Severity.CRITICAL, "AZURE_STORAGE_KEY"),

    # ── GitHub ───────────────────────────────────────────────────────
    (r"\bghp_[A-Za-z0-9]{36}\b", "GitHub Personal Access Token", Severity.CRITICAL, "GITHUB_PAT"),
    (r"\bgho_[A-Za-z0-9]{36}\b", "GitHub OAuth Token", Severity.CRITICAL, "GITHUB_OAUTH"),
    (r"\bghs_[A-Za-z0-9]{36}\b", "GitHub App Secret", Severity.CRITICAL, "GITHUB_APP_SECRET"),
    (r"\bghr_[A-Za-z0-9]{36}\b", "GitHub Refresh Token", Severity.CRITICAL, "GITHUB_REFRESH"),
    (r"\bv[0-9]\.[0-9a-f]{40}\b", "GitHub App Installation Token", Severity.CRITICAL, "GITHUB_INSTALL_TOKEN"),

    # ── Slack ────────────────────────────────────────────────────────
    (r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b", "Slack Token", Severity.CRITICAL, "SLACK_TOKEN"),
    (r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "Slack Webhook URL", Severity.CRITICAL, "SLACK_WEBHOOK"),

    # ── Stripe ───────────────────────────────────────────────────────
    (r"\bsk_live_[0-9a-zA-Z]{24,}\b", "Stripe Live Secret Key", Severity.CRITICAL, "STRIPE_LIVE_KEY"),
    (r"\brk_live_[0-9a-zA-Z]{24,}\b", "Stripe Live Restricted Key", Severity.CRITICAL, "STRIPE_RESTRICTED_KEY"),
    (r"\bsk_test_[0-9a-zA-Z]{24,}\b", "Stripe Test Secret Key", Severity.HIGH, "STRIPE_TEST_KEY"),

    # ── Other SaaS ───────────────────────────────────────────────────
    (r"\bSK[0-9a-fA-F]{32}\b", "Twilio Account SID/Auth Token", Severity.CRITICAL, "TWILIO_TOKEN"),
    (r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b", "SendGrid API Key", Severity.CRITICAL, "SENDGRID_KEY"),
    (r"\bnpm_[A-Za-z0-9]{36}\b", "NPM Access Token", Severity.CRITICAL, "NPM_TOKEN"),
    (r"\bpypi-[A-Za-z0-9_\-]{40,}\b", "PyPI API Token", Severity.CRITICAL, "PYPI_TOKEN"),
    (r"DCKR_PAT_[A-Za-z0-9]{24}", "Docker Hub Personal Access Token", Severity.CRITICAL, "DOCKER_PAT"),
    (r"\bAT-[A-Za-z0-9_\-]{20,}\b", "Atlassian/Jira Token", Severity.HIGH, "ATLASSIAN_TOKEN"),

    # ── Terraform Cloud / HashiCorp ──────────────────────────────────
    (r"\b[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_\-]{60,}\b", "Terraform Cloud Token", Severity.CRITICAL, "TFC_TOKEN"),
    (r"\bhvs\.[A-Za-z0-9]{24,}\b", "HashiCorp Vault Secret", Severity.CRITICAL, "VAULT_SECRET"),
    (r"\bhvb\.[A-Za-z0-9]{24,}\b", "HashiCorp Vault Batch Token", Severity.CRITICAL, "VAULT_BATCH"),

    # ── Private Keys ─────────────────────────────────────────────────
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----", "Private Key", Severity.CRITICAL, "PRIVATE_KEY"),
    (r"-----BEGIN CERTIFICATE-----", "TLS Certificate (may be private)", Severity.MEDIUM, "CERTIFICATE"),
    (r"-----BEGIN (RSA )?PUBLIC KEY-----", "Public Key", Severity.LOW, "PUBLIC_KEY"),

    # ── Database Connection Strings ───────────────────────────────────
    (r"(postgresql|postgres|mysql|mariadb|mssql|sqlserver)://[^:]+:[^@]+@[^\s\"']+", "Database connection string with credentials", Severity.CRITICAL, "DB_CONN_STRING"),
    (r"mongodb(\+srv)?://[^:]+:[^@]+@[^\s\"']+", "MongoDB connection string with credentials", Severity.CRITICAL, "MONGO_CONN_STRING"),
    (r"redis://(:[^@]+@)?[^\s\"']+", "Redis connection string", Severity.HIGH, "REDIS_CONN_STRING"),
    (r"amqps?://[^:]+:[^@]+@[^\s\"']+", "RabbitMQ/AMQP connection string", Severity.HIGH, "AMQP_CONN_STRING"),
    (r"Server=.{1,50};Database=.{1,50};(User Id|UID)=.{1,50};Password=.{1,100}", "MSSQL connection string", Severity.CRITICAL, "MSSQL_CONN_STRING"),

    # ── JWT Tokens ───────────────────────────────────────────────────
    (r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b", "JWT Token", Severity.HIGH, "JWT_TOKEN"),

    # ── Generic High-Entropy Credentials ─────────────────────────────
    (r"(password|passwd|pwd|secret|token|api_key|apikey|auth_key|access_key)\s*[=:]\s*['\"]?[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{12,}['\"]?", "Generic credential assignment", Severity.HIGH, "GENERIC_CREDENTIAL"),
    (r"Authorization:\s*Bearer\s+[A-Za-z0-9\-_\.]+\.[A-Za-z0-9\-_\.]+", "Bearer token in header", Severity.HIGH, "BEARER_TOKEN"),

    # ── Webhook URLs with Tokens ─────────────────────────────────────
    (r"https://hooks\.(slack\.com|discord\.com/api|teams\.microsoft\.com)/[A-Za-z0-9/\-_]+", "Webhook URL with token", Severity.HIGH, "WEBHOOK_URL"),

    # ── Kubernetes Secrets ───────────────────────────────────────────
    (r"kubeconfig|kubectl.*--token=[A-Za-z0-9\.\-_]+", "Kubernetes credential", Severity.HIGH, "K8S_CREDENTIAL"),

    # ── CI/CD Tokens ─────────────────────────────────────────────────
    (r"\bBITBUCKET_[A-Z_]+\s*=\s*[A-Za-z0-9\-_]{20,}\b", "Bitbucket credential", Severity.HIGH, "BITBUCKET_CRED"),
    (r"\bJENKINS_[A-Z_]+\s*=\s*[A-Za-z0-9\-_]{20,}\b", "Jenkins credential", Severity.HIGH, "JENKINS_CRED"),

    # ── AI / ML Platform Tokens ───────────────────────────────────────
    (r"\bhf_[A-Za-z0-9]{20,}\b", "Hugging Face API Token", Severity.CRITICAL, "HUGGINGFACE_TOKEN"),
    (r"\br8_[A-Za-z0-9]{20,}\b", "Replicate API Token", Severity.CRITICAL, "REPLICATE_TOKEN"),
    (r"\bsk-or-v1-[A-Za-z0-9]{20,}\b", "OpenRouter API Key", Severity.CRITICAL, "OPENROUTER_KEY"),
    (r"\bsk-or-[A-Za-z0-9\-_]{20,}\b", "OpenRouter API Key", Severity.CRITICAL, "OPENROUTER_KEY"),

    # ── Vector DB / Infrastructure ────────────────────────────────────
    (r"\bpcsk_[A-Za-z0-9]{20,}\b", "Pinecone API Key", Severity.CRITICAL, "PINECONE_KEY"),
    (r"\bpc-[A-Za-z0-9]{20,}\b", "Pinecone API Key (legacy)", Severity.CRITICAL, "PINECONE_KEY_LEGACY"),

    # ── Supabase ─────────────────────────────────────────────────────
    (r"SUPABASE_SERVICE_ROLE_KEY\s*[=:]\s*['\"]?eyJ[A-Za-z0-9\-_\.]+['\"]?", "Supabase Service Role Key", Severity.CRITICAL, "SUPABASE_SERVICE_KEY"),
    (r"SUPABASE_ANON_KEY\s*[=:]\s*['\"]?eyJ[A-Za-z0-9\-_\.]+['\"]?", "Supabase Anon Key", Severity.HIGH, "SUPABASE_ANON_KEY"),
    (r"https://[a-z0-9]{10,25}\.supabase\.co", "Supabase Project URL", Severity.MEDIUM, "SUPABASE_URL"),

    # ── Vercel ───────────────────────────────────────────────────────
    (r"\bvercel_[A-Za-z0-9]{20,}\b", "Vercel Token", Severity.CRITICAL, "VERCEL_TOKEN"),
    (r"\bVERCEL_TOKEN\s*[=:]\s*['\"]?[A-Za-z0-9]{20,}['\"]?", "Vercel Token (env)", Severity.CRITICAL, "VERCEL_TOKEN_ENV"),
    (r"\bvc_[A-Za-z0-9]{20,}\b", "Vercel Access Token", Severity.CRITICAL, "VERCEL_ACCESS_TOKEN"),

    # ── Cloudflare ───────────────────────────────────────────────────
    (r"\bCF_API_TOKEN\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?", "Cloudflare API Token", Severity.CRITICAL, "CF_API_TOKEN"),
    (r"\bCLOUDFLARE_API_TOKEN\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?", "Cloudflare API Token", Severity.CRITICAL, "CF_API_TOKEN_ENV"),

    # ── Linear ───────────────────────────────────────────────────────
    (r"\blin_api_[A-Za-z0-9]{20,}\b", "Linear API Key", Severity.CRITICAL, "LINEAR_API_KEY"),

    # ── Notion ───────────────────────────────────────────────────────
    (r"\bsecret_[A-Za-z0-9]{30,}\b", "Notion Integration Token", Severity.CRITICAL, "NOTION_TOKEN"),
    (r"\bNOTION_TOKEN\s*[=:]\s*['\"]?secret_[A-Za-z0-9]{30,}['\"]?", "Notion Token (env)", Severity.CRITICAL, "NOTION_TOKEN_ENV"),

    # ── Figma ────────────────────────────────────────────────────────
    (r"\bfigd_[A-Za-z0-9\-_]{20,}\b", "Figma Personal Access Token", Severity.CRITICAL, "FIGMA_PAT"),
    (r"\bFIGMA_TOKEN\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?", "Figma Token (env)", Severity.CRITICAL, "FIGMA_TOKEN_ENV"),
]


class SecretsDetector:
    def __init__(self) -> None:
        self._compiled = [
            (re.compile(p, re.IGNORECASE | re.MULTILINE), desc, sev, label)
            for p, desc, sev, label in _PATTERNS
        ]

    def scan(self, text: str) -> DetectionResult:
        findings: list[DetectionFinding] = []

        for pattern, desc, severity, label in self._compiled:
            m = pattern.search(text)
            if m:
                matched = m.group()
                # Redact most of the matched value in finding
                safe_match = matched[:6] + "***" if len(matched) > 9 else "***"
                findings.append(DetectionFinding(
                    category=DetectionCategory.PII_INPUT,
                    severity=severity,
                    confidence=0.95,
                    description=desc,
                    matched_pattern=f"[{label}: {safe_match}]",
                    position=m.start(),
                ))

        blocked = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
        )
        return DetectionResult(blocked=blocked, findings=findings)
