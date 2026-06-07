from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DetectionCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_INPUT = "pii_input"
    PII_OUTPUT = "pii_output"
    TOXIC = "toxic"
    TOKEN_LIMIT = "token_limit"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionFinding(BaseModel):
    category: DetectionCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    matched_pattern: str | None = None
    position: int | None = None  # character offset in text


class DetectionResult(BaseModel):
    blocked: bool
    findings: list[DetectionFinding] = []
    sanitized_text: str | None = None  # PII-masked version of text
    request_id: str = ""


class ArmorError(BaseModel):
    """Error response in OpenAI-compatible format so client apps don't break."""
    error: dict[str, Any] = Field(
        default_factory=lambda: {
            "message": "Request blocked by prompt-armor",
            "type": "content_policy_violation",
            "code": "prompt_armor_blocked",
            "findings": [],
        }
    )

    @classmethod
    def from_result(cls, result: DetectionResult, request_id: str) -> "ArmorError":
        return cls(
            error={
                "message": "Request blocked by prompt-armor security layer",
                "type": "content_policy_violation",
                "code": "prompt_armor_blocked",
                "request_id": request_id,
                "findings": [
                    {
                        "category": f.category.value,
                        "severity": f.severity.value,
                        "description": f.description,
                    }
                    for f in result.findings
                ],
            }
        )
