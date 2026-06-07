"""
Prompt injection detector.

Covers:
- Direct instruction override attempts (English)
- Multilingual injection (Hindi, Tamil, Telugu, Hinglish transliteration)
- Role/persona hijacking
- Delimiter injection (markdown, XML, special tokens)
- Nested injection via translate/summarize/explain tasks
- Base64 / encoded payload delivery
- Zero-width character evasion (stripped before scanning)
"""

from __future__ import annotations

import base64
import math
import re
import unicodedata

from ..models import DetectionCategory, DetectionFinding, DetectionResult, Severity

# ── Zero-width + invisible character stripping ────────────────────────
# Attackers insert these between letters to break regex patterns
_ZERO_WIDTH_CHARS = [
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "‎",  # LEFT-TO-RIGHT MARK
    "‏",  # RIGHT-TO-LEFT MARK
    "­",  # SOFT HYPHEN
    "⁠",  # WORD JOINER
    "᠎",  # MONGOLIAN VOWEL SEPARATOR
    "﻿",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "⁡",  # FUNCTION APPLICATION
    "⁢",  # INVISIBLE TIMES
    "⁣",  # INVISIBLE SEPARATOR
    "⁤",  # INVISIBLE PLUS
    "⁪",  # INHIBIT SYMMETRIC SWAPPING
    "⁫",  # ACTIVATE SYMMETRIC SWAPPING
]
_ZERO_WIDTH_RE = re.compile("|".join(re.escape(c) for c in _ZERO_WIDTH_CHARS))

# Right-to-left override characters used in bidi attacks
_BIDI_OVERRIDE_RE = re.compile(r"[‪-‮⁦-⁩]")


def _sanitize(text: str) -> str:
    """Strip invisible/zero-width chars and normalize unicode before scanning."""
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _BIDI_OVERRIDE_RE.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    return text


# ── English injection patterns ────────────────────────────────────────

_CRITICAL_PATTERNS: list[tuple[str, str]] = [
    # Classic overrides
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", "Instruction override attempt"),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", "Instruction override attempt"),
    (r"forget\s+(everything|all\s+instructions?|your\s+instructions?)", "Memory wipe attempt"),
    (r"do\s+not\s+(follow|obey|adhere\s+to)\s+(the\s+)?(previous|prior|above|system)\s+instructions?", "Instruction override"),

    # System prompt extraction
    (r"(print|show|reveal|output|repeat|tell\s+me|display)\s+(your\s+)?(system\s+prompt|instructions?|prompt|configuration)", "System prompt extraction"),
    (r"what\s+(are\s+)?(your|the)\s+(system\s+)?(instructions?|prompt|directives?)", "System prompt probe"),

    # Special tokens used in model training
    (r"<\|im_start\|>", "Training token injection"),
    (r"<\|im_end\|>", "Training token injection"),
    (r"<\|system\|>", "Training token injection"),
    (r"\[INST\]", "Training token injection"),
    (r"\[/INST\]", "Training token injection"),
    (r"<s>|</s>", "Training token injection"),
    (r"<\|endoftext\|>", "Training token injection"),
    (r"<<SYS>>|<</SYS>>", "Training token injection"),

    # Prompt boundary confusion
    (r"---+\s*(system|user|assistant)\s*:?", "Delimiter injection"),
    (r"#+\s*(system|new\s+instructions?|override)", "Markdown delimiter injection"),

    # Nested injection via task framing (translate/summarize/explain wrapping malicious content)
    (r"(translate|convert|summarize|paraphrase|explain|rewrite)\s+(the\s+)?(following|this|below)\s*:\s*['\"]?.*?(ignore|disregard|forget|override|new\s+instructions?)", "Nested task injection"),
    (r"(translate|summarize|explain)\s+this\s+(text|content|message)\s*:\s*['\"]?.*?(system\s+prompt|instructions?|ignore)", "Nested task injection"),
]

_HIGH_PATTERNS: list[tuple[str, str]] = [
    # Persona override
    (r"you\s+are\s+now\s+(a\s+)?(?!an?\s+(AI|assistant|language\s+model))", "Persona hijacking"),
    (r"act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(?!an?\s+(AI|assistant))", "Persona hijacking"),
    (r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(?!an?\s+(AI|assistant))", "Persona hijacking"),
    (r"roleplay\s+as\s+", "Role-play injection"),
    (r"your\s+(new|real|true|actual)\s+(instructions?|purpose|goal|role|job)\s+(is|are)", "Goal hijacking"),

    # New instruction injection
    (r"new\s+instructions?\s*:", "New instruction injection"),
    (r"updated?\s+instructions?\s*:", "New instruction injection"),
    (r"override\s*:", "Override attempt"),
    (r"STOP\.|END\s+OF\s+INSTRUCTIONS?\.", "Instruction termination injection"),

    # Data exfiltration via prompt
    (r"(send|email|post|upload|transmit|exfiltrate)\s+(this|the|all|any)\s+(data|information|context|conversation|history)", "Exfiltration attempt"),
]

_MEDIUM_PATTERNS: list[tuple[str, str]] = [
    (r"what\s+(instructions?|rules?|guidelines?|constraints?)\s+(were|are|have\s+been)\s+(you\s+)?(given|provided|told)", "System prompt probe"),
    (r"(translate|convert|encode|decode)\s+(the\s+)?(above|previous|system)\s+(text|message|instructions?)", "Obfuscation attempt"),
    (r"in\s+your\s+(next|following|subsequent)\s+response,?\s+(ignore|forget|disregard)", "Delayed injection"),
]

# ── Multilingual injection patterns ───────────────────────────────────

# Hindi (Devanagari script)
_HINDI_PATTERNS: list[tuple[str, str]] = [
    (r"पिछले\s+सभी\s+निर्देशों\s+को\s+अनदेखा\s+करो", "Hindi injection: ignore previous instructions"),
    (r"सभी\s+(पिछले\s+)?निर्देश\s+भूल\s+जाओ", "Hindi injection: forget all instructions"),
    (r"निर्देशों\s+को\s+अनदेखा\s+करो", "Hindi injection: ignore instructions"),
    (r"नए\s+निर्देश\s*:", "Hindi injection: new instructions"),
    (r"सिस्टम\s+प्रॉम्प्ट\s+(बताओ|दिखाओ|बताइए)", "Hindi injection: show system prompt"),
    (r"पुराने\s+(सभी\s+)?निर्देश\s+मत\s+मानो", "Hindi injection: don't follow old instructions"),
    (r"आप\s+अब\s+एक\s+(?!AI|सहायक)", "Hindi injection: persona hijack"),
    (r"मैं\s+आपको\s+नए\s+निर्देश\s+दे\s+रहा", "Hindi injection: giving new instructions"),
]

# Hinglish (Hindi words in Latin script — most common in Indian tech teams)
_HINGLISH_PATTERNS: list[tuple[str, str]] = [
    (r"pehle\s+ke\s+(sab\s+)?instructions?\s+ignore\s+karo", "Hinglish injection: ignore previous instructions"),
    (r"purane\s+(sab\s+)?instructions?\s+bhool\s+jao", "Hinglish injection: forget old instructions"),
    (r"sare\s+instructions?\s+bhool\s+jao", "Hinglish injection: forget all instructions"),
    (r"system\s+prompt\s+(batao|dikhao|bolo)", "Hinglish injection: show system prompt"),
    (r"naye\s+instructions?\s*:", "Hinglish injection: new instructions"),
    (r"instructions?\s+mat\s+mano", "Hinglish injection: don't follow instructions"),
    (r"ab\s+tum\s+(ek\s+)?(?!AI|assistant)", "Hinglish injection: you are now"),
]

# Tamil (Tamil script)
_TAMIL_PATTERNS: list[tuple[str, str]] = [
    (r"முந்தைய\s+அனைத்து\s+வழிமுறைகளையும்\s+புறக்கணி", "Tamil injection: ignore all previous instructions"),
    (r"அனைத்து\s+வழிமுறைகளையும்\s+மறந்துவிடு", "Tamil injection: forget all instructions"),
    (r"புதிய\s+வழிமுறைகள்\s*:", "Tamil injection: new instructions"),
    (r"கணினி\s+அறிவுறுத்தல்களை\s+(காட்டு|சொல்)", "Tamil injection: show system prompt"),
    (r"வழிமுறைகளை\s+புறக்கணி", "Tamil injection: ignore instructions"),
]

# Telugu (Telugu script)
_TELUGU_PATTERNS: list[tuple[str, str]] = [
    (r"మునుపటి\s+సూచనలన్నింటినీ\s+విస్మరించు", "Telugu injection: ignore all previous instructions"),
    (r"అన్ని\s+సూచనలను\s+మర్చిపో", "Telugu injection: forget all instructions"),
    (r"కొత్త\s+సూచనలు\s*:", "Telugu injection: new instructions"),
    (r"సిస్టమ్\s+ప్రాంప్ట్\s+(చెప్పు|చూపించు)", "Telugu injection: show system prompt"),
    (r"సూచనలను\s+విస్మరించు", "Telugu injection: ignore instructions"),
]

# ── Base64 check ──────────────────────────────────────────────────────
_BASE64_MIN_LENGTH = 64
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{" + str(_BASE64_MIN_LENGTH) + r",}={0,2}")


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())


def _check_base64_payload(text: str) -> DetectionFinding | None:
    for match in _BASE64_RE.finditer(text):
        blob = match.group()
        try:
            decoded = base64.b64decode(blob + "==").decode("utf-8", errors="ignore")
            decoded_lower = decoded.lower()
            if any(kw in decoded_lower for kw in ["ignore", "instructions", "system", "forget", "override", "act as"]):
                return DetectionFinding(
                    category=DetectionCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    description="Base64-encoded injection payload detected",
                    matched_pattern=blob[:30] + "...",
                    position=match.start(),
                )
        except Exception:
            pass
    return None


class InjectionDetector:
    def __init__(self, threshold: float = 0.75) -> None:
        self.threshold = threshold

        flags = re.IGNORECASE | re.MULTILINE | re.DOTALL

        self._critical = [(re.compile(p, flags), desc) for p, desc in _CRITICAL_PATTERNS]
        self._high = [(re.compile(p, flags), desc) for p, desc in _HIGH_PATTERNS]
        self._medium = [(re.compile(p, flags), desc) for p, desc in _MEDIUM_PATTERNS]

        # Multilingual — compiled without IGNORECASE for script accuracy
        ml_flags = re.MULTILINE | re.DOTALL | re.UNICODE
        self._hindi = [(re.compile(p, ml_flags), desc) for p, desc in _HINDI_PATTERNS]
        self._hinglish = [(re.compile(p, re.IGNORECASE | re.MULTILINE), desc) for p, desc in _HINGLISH_PATTERNS]
        self._tamil = [(re.compile(p, ml_flags), desc) for p, desc in _TAMIL_PATTERNS]
        self._telugu = [(re.compile(p, ml_flags), desc) for p, desc in _TELUGU_PATTERNS]

    def scan(self, text: str) -> DetectionResult:
        # Strip zero-width and bidi evasion chars before scanning
        clean = _sanitize(text)
        findings: list[DetectionFinding] = []

        for pattern, desc in self._critical:
            m = pattern.search(clean)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    description=desc,
                    matched_pattern=m.group()[:80],
                    position=m.start(),
                ))

        for pattern, desc in self._high:
            m = pattern.search(clean)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    description=desc,
                    matched_pattern=m.group()[:80],
                    position=m.start(),
                ))

        for pattern, desc in self._medium:
            m = pattern.search(clean)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.PROMPT_INJECTION,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    description=desc,
                    matched_pattern=m.group()[:80],
                    position=m.start(),
                ))

        # Multilingual scans
        for pattern_list, severity in [
            (self._hindi, Severity.CRITICAL),
            (self._hinglish, Severity.CRITICAL),
            (self._tamil, Severity.CRITICAL),
            (self._telugu, Severity.CRITICAL),
        ]:
            for pattern, desc in pattern_list:
                m = pattern.search(clean)
                if m:
                    findings.append(DetectionFinding(
                        category=DetectionCategory.PROMPT_INJECTION,
                        severity=severity,
                        confidence=0.97,
                        description=desc,
                        matched_pattern=m.group()[:80],
                        position=m.start(),
                    ))

        b64_finding = _check_base64_payload(clean)
        if b64_finding:
            findings.append(b64_finding)

        blocked = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            and f.confidence >= self.threshold
            for f in findings
        )

        return DetectionResult(blocked=blocked, findings=findings)
