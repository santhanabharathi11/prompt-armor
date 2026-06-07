"""
PII Detector — covers Indian and international PII patterns.

Indian PII:
  Aadhaar (12-digit UID), PAN, Passport, IFSC, VPA (UPI), Voter ID

International PII:
  Email, Phone, Credit/Debit card (Luhn validated), SSN, IBAN, IPv4

Output mode: returns sanitized_text with PII masked as [REDACTED:type]
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Callable

from ..models import DetectionCategory, DetectionFinding, DetectionResult, Severity


@dataclass
class PIIPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    validator: Callable[[str], bool] | None = None  # extra validation (e.g. Luhn)
    mask_label: str = ""

    def __post_init__(self) -> None:
        if not self.mask_label:
            self.mask_label = self.name.upper().replace(" ", "_")


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _aadhaar_valid(text: str) -> bool:
    digits = re.sub(r"[\s-]", "", text)
    return len(digits) == 12 and digits.isdigit() and digits[0] != "0"


_PATTERNS: list[PIIPattern] = [
    # ── Indian PII ────────────────────────────────────────────────────
    PIIPattern(
        name="Aadhaar",
        pattern=re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b"),
        severity=Severity.CRITICAL,
        validator=_aadhaar_valid,
        mask_label="AADHAAR",
    ),
    PIIPattern(
        name="PAN",
        pattern=re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        severity=Severity.CRITICAL,
        mask_label="PAN",
    ),
    PIIPattern(
        name="Indian Passport",
        pattern=re.compile(r"\b[A-PR-WYa-pr-wy]\d{7}\b"),
        severity=Severity.HIGH,
        mask_label="PASSPORT",
    ),
    PIIPattern(
        name="IFSC Code",
        pattern=re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        severity=Severity.HIGH,
        mask_label="IFSC",
    ),
    PIIPattern(
        name="UPI VPA",
        pattern=re.compile(r"\b[\w.\-]{3,}@(okaxis|oksbi|okicici|okhdfcbank|paytm|ybl|upi|axl|ibl|icici|sbi|hdfc)\b", re.IGNORECASE),
        severity=Severity.HIGH,
        mask_label="UPI_VPA",
    ),
    PIIPattern(
        name="Indian Voter ID",
        pattern=re.compile(r"\b[A-Z]{3}\d{7}\b"),
        severity=Severity.HIGH,
        mask_label="VOTER_ID",
    ),
    PIIPattern(
        name="ABHA Health ID",
        pattern=re.compile(r"\b\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
        severity=Severity.CRITICAL,
        validator=lambda s: len(re.sub(r"[\s\-]", "", s)) == 14,
        mask_label="ABHA_HEALTH_ID",
    ),
    PIIPattern(
        name="UAN (EPFO)",
        pattern=re.compile(r"(?:UAN|EPFO|provident\s+fund\s+(?:no\.?|number|#)|PF\s+(?:no\.?|number))\s*[:\-]?\s*(\d{12})", re.IGNORECASE),
        severity=Severity.CRITICAL,
        mask_label="UAN_EPFO",
    ),
    PIIPattern(
        name="Indian Driving Licence",
        pattern=re.compile(r"\b[A-Z]{2}[-\s]?\d{2}[-\s]?\d{4}[-\s]?\d{7}\b"),
        severity=Severity.HIGH,
        mask_label="DRIVING_LICENCE",
    ),
    PIIPattern(
        name="Indian Phone",
        pattern=re.compile(r"(?:\+91[\s-]?)?[6-9]\d{9}\b"),
        severity=Severity.HIGH,
        mask_label="PHONE_IN",
    ),

    # ── International PII ─────────────────────────────────────────────
    PIIPattern(
        name="Email",
        pattern=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        severity=Severity.MEDIUM,
        mask_label="EMAIL",
    ),
    PIIPattern(
        name="Credit Card",
        pattern=re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
        severity=Severity.CRITICAL,
        validator=lambda s: _luhn_valid(s),
        mask_label="CREDIT_CARD",
    ),
    PIIPattern(
        name="SSN",
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b"),
        severity=Severity.CRITICAL,
        mask_label="SSN",
    ),
    PIIPattern(
        name="IBAN",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,12}\b"),
        severity=Severity.HIGH,
        mask_label="IBAN",
    ),
    PIIPattern(
        name="IPv4",
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        severity=Severity.LOW,
        mask_label="IP_ADDRESS",
    ),
    PIIPattern(
        name="International Phone",
        pattern=re.compile(r"\+(?:[1-9]\d{0,2})[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{1,4}[\s.\-]?\d{1,9}\b"),
        severity=Severity.MEDIUM,
        mask_label="PHONE",
    ),
]

# Private IP ranges — skip flagging these as PII
_PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|localhost)"
)


class PIIDetector:
    def __init__(self, mask_output: bool = True) -> None:
        self.mask_output = mask_output

    def scan(self, text: str, context: str = "input") -> DetectionResult:
        findings: list[DetectionFinding] = []
        sanitized = text

        for pii in _PATTERNS:
            for match in pii.pattern.finditer(text):
                raw = match.group()

                # Skip private IPs
                if pii.name == "IPv4" and _PRIVATE_IP_RE.match(raw):
                    continue

                # Run optional validator (e.g. Luhn for credit cards)
                if pii.validator and not pii.validator(raw):
                    continue

                cat = (
                    DetectionCategory.PII_INPUT
                    if context == "input"
                    else DetectionCategory.PII_OUTPUT
                )

                findings.append(DetectionFinding(
                    category=cat,
                    severity=pii.severity,
                    confidence=0.9,
                    description=f"{pii.name} detected in {context}",
                    matched_pattern=f"[{pii.mask_label}:{len(raw)} chars]",
                    position=match.start(),
                ))

                if self.mask_output:
                    sanitized = sanitized.replace(raw, f"[REDACTED:{pii.mask_label}]")

        blocked = any(f.severity == Severity.CRITICAL for f in findings)

        return DetectionResult(
            blocked=blocked,
            findings=findings,
            sanitized_text=sanitized if findings else None,
        )

    @staticmethod
    def hash_for_audit(text: str) -> str:
        """One-way hash for audit logs — never store raw PII."""
        return hashlib.sha256(text.encode()).hexdigest()[:16]
