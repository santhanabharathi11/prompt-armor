"""
Company-configured detector.

Loads from prompt_armor.yaml (or ARMOR_COMPANY_CONFIG env var pointing to a file).
Blocks company-specific identifiers: internal domains, AWS/GCP/Azure account IDs,
employee ID formats, customer account patterns, and custom keyword blocklists.

If no config file found, this detector is a no-op.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from ..models import DetectionCategory, DetectionFinding, DetectionResult, Severity


def _load_config() -> dict:
    config_paths = [
        os.environ.get("ARMOR_COMPANY_CONFIG", ""),
        "config/prompt_armor.yaml",
        "prompt_armor.yaml",
        str(Path.home() / ".prompt_armor.yaml"),
    ]
    for path in config_paths:
        if path and Path(path).exists():
            with open(path) as f:
                return yaml.safe_load(f) or {}
    return {}


class CompanyDetector:
    """
    Builds detection rules from company config YAML.
    All patterns are loaded once at startup.
    """

    def __init__(self) -> None:
        self._rules: list[tuple[re.Pattern[str], str, Severity, str]] = []
        self._keyword_patterns: list[re.Pattern[str]] = []
        self._load()

    def _load(self) -> None:
        cfg = _load_config()
        if not cfg:
            return

        company = cfg.get("company", {})
        name = company.get("name", "Company")

        # ── Internal email domains ────────────────────────────────────
        for domain in company.get("internal_domains", []):
            pattern = re.compile(
                r"[\w._%+\-]+@" + re.escape(domain), re.IGNORECASE
            )
            self._rules.append((
                pattern,
                f"Internal company email ({domain})",
                Severity.HIGH,
                "INTERNAL_EMAIL",
            ))

        # ── Internal URLs / hostnames ─────────────────────────────────
        for domain in company.get("internal_domains", []):
            pattern = re.compile(
                r"https?://[\w\-\.]*" + re.escape(domain) + r"[\w/\-?=#&.]*",
                re.IGNORECASE,
            )
            self._rules.append((
                pattern,
                f"Internal URL ({domain})",
                Severity.HIGH,
                "INTERNAL_URL",
            ))

        # ── AWS Account IDs (company-specific) ───────────────────────
        for account_id in company.get("aws_account_ids", []):
            acct = str(account_id).replace("-", "")
            pattern = re.compile(r"\b" + re.escape(acct) + r"\b")
            self._rules.append((
                pattern,
                f"Company AWS Account ID ({acct[:4]}****)",
                Severity.CRITICAL,
                "COMPANY_AWS_ACCOUNT",
            ))

        # ── GCP Project IDs ───────────────────────────────────────────
        for project_id in company.get("gcp_project_ids", []):
            pattern = re.compile(r"\b" + re.escape(str(project_id)) + r"\b", re.IGNORECASE)
            self._rules.append((
                pattern,
                f"Company GCP Project ID ({project_id})",
                Severity.CRITICAL,
                "COMPANY_GCP_PROJECT",
            ))

        # ── Azure Subscription IDs ────────────────────────────────────
        for sub_id in company.get("azure_subscription_ids", []):
            pattern = re.compile(r"\b" + re.escape(str(sub_id)) + r"\b", re.IGNORECASE)
            self._rules.append((
                pattern,
                f"Company Azure Subscription ID",
                Severity.CRITICAL,
                "COMPANY_AZURE_SUB",
            ))

        # ── Employee ID format ────────────────────────────────────────
        emp_format = company.get("employee_id_pattern", "")
        if emp_format:
            try:
                pattern = re.compile(emp_format, re.IGNORECASE)
                self._rules.append((
                    pattern,
                    "Company Employee ID",
                    Severity.HIGH,
                    "EMPLOYEE_ID",
                ))
            except re.error:
                pass

        # ── Customer account ID format ─────────────────────────────────
        cust_format = company.get("customer_account_pattern", "")
        if cust_format:
            try:
                pattern = re.compile(cust_format, re.IGNORECASE)
                self._rules.append((
                    pattern,
                    "Customer Account ID",
                    Severity.HIGH,
                    "CUSTOMER_ACCOUNT_ID",
                ))
            except re.error:
                pass

        # ── Custom keyword blocklist ──────────────────────────────────
        for keyword in company.get("blocked_keywords", []):
            try:
                kw_pattern = re.compile(r"\b" + re.escape(keyword) + r"\b", re.IGNORECASE)
                self._keyword_patterns.append(kw_pattern)
            except re.error:
                pass

        # ── Custom regex patterns ─────────────────────────────────────
        for entry in company.get("custom_patterns", []):
            pattern_str = entry.get("pattern", "")
            label = entry.get("label", "custom")
            severity_str = entry.get("severity", "high").upper()
            severity = getattr(Severity, severity_str, Severity.HIGH)
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                self._rules.append((
                    pattern,
                    f"Custom pattern: {label}",
                    severity,
                    f"CUSTOM_{label.upper().replace(' ', '_')}",
                ))
            except re.error:
                pass

    def scan(self, text: str) -> DetectionResult:
        if not self._rules and not self._keyword_patterns:
            return DetectionResult(blocked=False, findings=[])

        findings: list[DetectionFinding] = []

        for pattern, desc, severity, label in self._rules:
            m = pattern.search(text)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.PII_INPUT,
                    severity=severity,
                    confidence=0.97,
                    description=desc,
                    matched_pattern=f"[{label}: {m.group()[:40]}]",
                    position=m.start(),
                ))

        for kw_pattern in self._keyword_patterns:
            m = kw_pattern.search(text)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.PII_INPUT,
                    severity=Severity.HIGH,
                    confidence=0.99,
                    description=f"Blocked keyword detected",
                    matched_pattern=f"[KEYWORD: {m.group()}]",
                    position=m.start(),
                ))

        blocked = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        return DetectionResult(blocked=blocked, findings=findings)

    @property
    def is_configured(self) -> bool:
        return bool(self._rules or self._keyword_patterns)
