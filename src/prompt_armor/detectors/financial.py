"""
Financial data detector — universal patterns.

Covers:
  GST, SWIFT/BIC, Indian bank accounts, MICR,
  Salary/CTC patterns, Revenue/ARR/deal amounts,
  Fundraising data, P&L keywords with numbers,
  Equity/ESOP disclosures
"""

from __future__ import annotations

import re

from ..models import DetectionCategory, DetectionFinding, DetectionResult, Severity

# Currency + large number helpers
_INR = r"(?:₹|INR|Rs\.?)\s*"
_USD = r"(?:\$|USD)\s*"
_LARGE_NUM = r"\d{1,3}(?:,\d{2,3})*(?:\.\d+)?\s*(?:Cr|L|K|M|B|Mn|Bn|lakh|crore|million|billion|thousand)?"

_PATTERNS: list[tuple[str, str, Severity, str]] = [

    # ── Indian Tax & Business IDs ────────────────────────────────────
    (
        r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}Z[A-Z\d]\b",
        "GST Identification Number (GSTIN)",
        Severity.CRITICAL,
        "GSTIN",
    ),
    (
        r"\bU\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b",
        "Company Identification Number (CIN)",
        Severity.HIGH,
        "CIN",
    ),
    (
        r"\b[A-Z]{4}[0-9]{7}\b",
        "Indian MICR Code",
        Severity.MEDIUM,
        "MICR",
    ),

    # ── SWIFT / BIC ───────────────────────────────────────────────────
    (
        r"\b(?:SWIFT|BIC|bank\s+code|routing)\s*[:#]?\s*[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
        "SWIFT/BIC Code",
        Severity.HIGH,
        "SWIFT_BIC",
    ),

    # ── Indian Bank Account (with context) ────────────────────────────
    (
        r"(?:account\s*(?:number|no\.?|#)\s*:?\s*)(\d{9,18})\b",
        "Bank account number",
        Severity.CRITICAL,
        "BANK_ACCOUNT",
    ),
    (
        r"(?:acc\.?\s*no\.?\s*:?\s*)(\d{9,18})\b",
        "Bank account number",
        Severity.CRITICAL,
        "BANK_ACCOUNT",
    ),

    # ── Salary / CTC / Compensation ───────────────────────────────────
    (
        r"(?:CTC|ctc|salary|compensation|package)\s*(?:of|is|:)?\s*" + _INR + _LARGE_NUM,
        "Salary/CTC disclosure",
        Severity.HIGH,
        "SALARY_CTC",
    ),
    (
        r"(?:fixed|variable|bonus|hike|increment|appraisal)\s*(?:of|:)?\s*" + _INR + _LARGE_NUM,
        "Compensation component disclosure",
        Severity.HIGH,
        "COMPENSATION",
    ),
    (
        r"(?:offer(?:ed)?|joining)\s+(?:bonus|amount)\s*(?:of|:)?\s*" + _INR + _LARGE_NUM,
        "Joining bonus disclosure",
        Severity.HIGH,
        "JOINING_BONUS",
    ),
    (
        r"\bESOPs?\s*(?:of|worth|valued|:)?\s*" + _INR + _LARGE_NUM,
        "ESOP value disclosure",
        Severity.HIGH,
        "ESOP_VALUE",
    ),

    # ── Revenue / ARR / MRR ───────────────────────────────────────────
    (
        r"\b(?:ARR|MRR|revenue|turnover|GMV|GTV|NRR|GRR)\s*(?:of|is|was|:)?\s*(?:" + _INR + "|" + _USD + ")" + _LARGE_NUM,
        "Revenue/ARR/MRR disclosure",
        Severity.CRITICAL,
        "REVENUE_ARR",
    ),
    (
        r"\b(?:Q[1-4]|FY\s*\d{2,4}|FQ[1-4])\s+(?:revenue|ARR|sales|bookings)\s*(?:of|is|was|:)?\s*(?:" + _INR + "|" + _USD + r")?" + _LARGE_NUM,
        "Quarterly financial disclosure",
        Severity.CRITICAL,
        "QUARTERLY_FINANCIALS",
    ),

    # ── Deal / Contract Values ────────────────────────────────────────
    (
        r"(?:deal|contract|ACV|TCV|invoice)\s*(?:value|worth|size|amount)?\s*(?:of|is|:)?\s*(?:" + _INR + "|" + _USD + ")" + _LARGE_NUM,
        "Deal/contract value",
        Severity.HIGH,
        "DEAL_VALUE",
    ),
    (
        r"(?:closed|won|signed)\s+(?:a\s+)?(?:deal|contract|customer)\s+(?:for|at|worth)\s*(?:" + _INR + "|" + _USD + ")" + _LARGE_NUM,
        "Deal closure amount",
        Severity.HIGH,
        "DEAL_CLOSED",
    ),

    # ── Fundraising / Valuation ───────────────────────────────────────
    (
        r"(?:Series\s*[A-F]|Seed|Pre-seed|Bridge|IPO|round)\s+(?:of|at|raising|raised)?\s*(?:" + _INR + "|" + _USD + ")" + _LARGE_NUM,
        "Fundraising round amount",
        Severity.CRITICAL,
        "FUNDRAISING",
    ),
    (
        r"(?:valuation|valued)\s+(?:at|of)?\s*(?:" + _INR + "|" + _USD + ")" + _LARGE_NUM,
        "Company valuation",
        Severity.CRITICAL,
        "VALUATION",
    ),
    (
        r"(?:term\s*sheet|LOI|letter\s*of\s*intent)",
        "Term sheet / LOI mention",
        Severity.HIGH,
        "TERM_SHEET",
    ),

    # ── P&L / Budget Data ────────────────────────────────────────────
    (
        r"(?:EBITDA|PAT|PBT|gross\s*profit|net\s*profit|operating\s*profit)\s*(?:of|is|:)?\s*(?:" + _INR + "|" + _USD + r")?" + _LARGE_NUM,
        "P&L data",
        Severity.CRITICAL,
        "PNL_DATA",
    ),
    (
        r"(?:burn\s*rate|runway|cash\s*balance|cash\s*in\s*bank)\s*(?:of|is|:)?\s*(?:" + _INR + "|" + _USD + r")?" + _LARGE_NUM,
        "Cash/burn rate disclosure",
        Severity.CRITICAL,
        "BURN_RATE",
    ),
    (
        r"(?:budget|approved|allocated)\s+(?:for|of)?\s*(?:" + _INR + "|" + _USD + ")" + _LARGE_NUM,
        "Budget data",
        Severity.HIGH,
        "BUDGET",
    ),

    # ── M&A ──────────────────────────────────────────────────────────
    (
        r"\b(?:acquisition|acquiring|merger|acqui-?hire|takeover)\s+(?:of|target|talks|discussion)",
        "M&A activity mention",
        Severity.CRITICAL,
        "MA_ACTIVITY",
    ),
    (
        r"(?:due\s*diligence|data\s*room|VDR)\s+(?:for|on|of)",
        "Due diligence mention",
        Severity.HIGH,
        "DUE_DILIGENCE",
    ),
]


class FinancialDetector:
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
                findings.append(DetectionFinding(
                    category=DetectionCategory.PII_INPUT,
                    severity=severity,
                    confidence=0.88,
                    description=desc,
                    matched_pattern=f"[{label}: {m.group()[:60]}]",
                    position=m.start(),
                ))

        blocked = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
        )
        return DetectionResult(blocked=blocked, findings=findings)
