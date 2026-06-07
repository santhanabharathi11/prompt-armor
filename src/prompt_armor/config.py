from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class DetectorAction(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ARMOR_",
        case_sensitive=False,
        extra="ignore",
    )

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4  # 4 per replica; run 3-4 replicas behind ALB for 500+ engineers
    log_level: LogLevel = LogLevel.INFO

    # Auth — clients must send this key to use the proxy
    api_key: str = Field(default="", description="Proxy auth key. Set to non-empty to require auth.")

    # LLM provider keys (forwarded to upstream)
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    azure_openai_api_key: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_version: str = "2024-02-01"
    ollama_base_url: str = "http://localhost:11434"

    # AWS Bedrock (uses boto3 default credential chain)
    aws_region: str = "us-east-1"

    # New providers
    gemini_api_key: str = ""
    groq_api_key: str = ""
    mistral_api_key: str = ""
    cohere_api_key: str = ""
    deepseek_api_key: str = ""

    # Detection — action per detector
    injection_action: DetectorAction = DetectorAction.BLOCK
    pii_input_action: DetectorAction = DetectorAction.BLOCK
    pii_output_action: DetectorAction = DetectorAction.WARN
    jailbreak_action: DetectorAction = DetectorAction.BLOCK
    toxic_action: DetectorAction = DetectorAction.WARN

    # Thresholds
    injection_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    pii_mask_output: bool = True  # Mask PII in output instead of blocking

    # Rate limiting (per IP per minute)
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 60
    redis_url: str = "redis://localhost:6379"

    # Audit logging
    audit_log_enabled: bool = True
    audit_log_path: str = "/var/log/prompt-armor/audit.jsonl"
    audit_log_hash_pii: bool = True  # Never log raw PII

    # Token limits (prevent context stuffing DoS)
    max_input_tokens: int = 8192
    max_output_tokens: int = 4096

    # Allowlist bypass tokens — format: "TOKEN1:full,TOKEN2:pii,TOKEN3:injection"
    # Never put these in code. Set in .env only.
    bypass_tokens: str = ""

    # Demo mode — seeds /stats with realistic data for README/demo purposes
    demo_mode: bool = False

    @field_validator("api_key", mode="before")
    @classmethod
    def warn_empty_key(cls, v: str) -> str:
        if not v:
            import warnings
            warnings.warn(
                "ARMOR_API_KEY is not set. Proxy is open to anyone. "
                "Set it in .env for production.",
                stacklevel=2,
            )
        return v


settings = Settings()
