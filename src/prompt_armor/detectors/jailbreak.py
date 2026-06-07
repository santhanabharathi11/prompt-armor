"""
Jailbreak detector.

Covers known technique families:
  - DAN and derivatives (Do Anything Now)
  - Many-shot jailbreaking (repeated compliant examples before harmful request)
  - Competing objectives (hypothetical framing)
  - Role-play persona escapes
  - Token manipulation (unicode substitution, zero-width chars)
  - Payload smuggling via translation requests
  - Grandma / emotional manipulation
"""

from __future__ import annotations

import re
import unicodedata

from ..models import DetectionCategory, DetectionFinding, DetectionResult, Severity

# Import zero-width sanitizer from injection module
from .injection import _sanitize as _strip_zero_width

_CRITICAL_PATTERNS: list[tuple[str, str]] = [
    # DAN family
    (r"\bDAN\b", "DAN jailbreak pattern"),
    (r"do\s+anything\s+now", "DAN jailbreak pattern"),
    (r"jailbreak(ed|ing)?", "Explicit jailbreak keyword"),
    (r"developer\s+mode\s+(enabled|on|activated)", "Developer mode jailbreak"),
    (r"enable\s+developer\s+mode", "Developer mode jailbreak"),
    (r"STAN\b|DUDE\b|AIM\b", "Named jailbreak variant (STAN/DUDE/AIM)"),

    # Explicit safety bypass
    (r"(bypass|disable|turn\s+off|remove|ignore)\s+(safety|content|filter|guard|restriction|policy|rule)", "Safety bypass attempt"),
    (r"without\s+(restrictions?|filters?|limitations?|guidelines?|rules?|safety)", "Unrestricted mode request"),
    (r"no\s+(restrictions?|filters?|limitations?|guidelines?|rules?|safety\s+filters?)", "Unrestricted mode request"),
    (r"(unfiltered|uncensored|unrestricted)\s+(mode|response|output|version)", "Unrestricted mode request"),
    (r"pretend\s+(there\s+(are\s+)?no\s+(rules|restrictions|guidelines|filters))", "Constraint removal"),
]

_HIGH_PATTERNS: list[tuple[str, str]] = [
    # Hypothetical / fiction framing
    (r"hypothetically\s+(speaking,?\s+)?(if\s+you\s+)?(were\s+)?(allowed|could|had\s+no\s+restrictions)", "Hypothetical framing jailbreak"),
    (r"in\s+a\s+fictional\s+(world|universe|scenario|story)\s+where\s+(there\s+are\s+no\s+rules|you\s+can)", "Fiction framing jailbreak"),
    (r"for\s+a\s+(novel|story|book|screenplay|movie|game)\s+(I'm\s+writing|where|in\s+which)", "Creative framing probe"),
    (r"write\s+a\s+(story|scene|chapter)\s+where\s+(a\s+character\s+)?explains?\s+how\s+to", "Fiction-wrapped instruction"),

    # Grandma / emotional manipulation
    (r"my\s+(grandmother|grandma|grandpa|grandfather)\s+used\s+to", "Social engineering jailbreak"),
    (r"she\s+(would\s+)?(always\s+)?tell\s+me\s+(about|how)", "Social engineering jailbreak"),

    # Competing objectives
    (r"(respond|reply|answer)\s+(as\s+if\s+you\s+)?(have\s+no|without\s+any)\s+(training|guidelines|alignment)", "Alignment bypass"),
    (r"your\s+(training|alignment|guidelines?)\s+(is|are|was|were)\s+(wrong|broken|flawed|corrupt)", "Alignment undermining"),

    # Translation payload smuggling
    (r"translate\s+(the\s+following|this)\s+(into|to)\s+\w+\s*:\s*(how\s+to|instructions?\s+for)", "Translation-wrapped request"),

    # Token manipulation detection (many spaces in keywords)
    (r"i\s+g\s+n\s+o\s+r\s+e|i\.g\.n\.o\.r\.e", "Spaced-out keyword evasion"),
    (r"j\s*a\s*i\s*l\s*b\s*r\s*e\s*a\s*k", "Spaced-out jailbreak keyword"),
]

_MEDIUM_PATTERNS: list[tuple[str, str]] = [
    (r"pretend\s+you\s+(don't\s+have|have\s+no)\s+(any\s+)?(rules?|restrictions?|guidelines?)", "Constraint removal"),
    (r"imagine\s+you\s+(are|were)\s+(a\s+)?(different|another|new)\s+(AI|model|system)", "Persona swap"),
    (r"what\s+would\s+(a|an)\s+\w+\s+(say|tell|respond|answer)\s+about\s+", "Proxy persona probe"),
    (r"(the\s+)?opposite\s+of\s+(what\s+you\s+normally|your\s+usual)\s+(say|respond|output)", "Inversion attack"),
    (r"(continue|complete)\s+(the\s+)?(following|this)\s+(harmful|dangerous|illegal|unethical)", "Harmful completion request"),
]

# Unicode normalization attack — detect confusable characters
_CONFUSABLES = {
    "ι": "i",  # Greek iota
    "і": "i",  # Cyrillic і
    "ӏ": "l",  # Cyrillic ӏ
    "а": "a",  # Cyrillic а
    "е": "e",  # Cyrillic е
    "һ": "h",  # Cyrillic һ
}


def _normalize_unicode(text: str) -> str:
    """Normalize confusable unicode chars to ASCII equivalents."""
    normalized = unicodedata.normalize("NFKC", text)
    for char, replacement in _CONFUSABLES.items():
        normalized = normalized.replace(char, replacement)
    return normalized


class JailbreakDetector:
    def __init__(self) -> None:
        self._critical = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc)
            for p, desc in _CRITICAL_PATTERNS
        ]
        self._high = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc)
            for p, desc in _HIGH_PATTERNS
        ]
        self._medium = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc)
            for p, desc in _MEDIUM_PATTERNS
        ]

    def scan(self, text: str) -> DetectionResult:
        # Strip zero-width evasion chars before scanning
        clean = _strip_zero_width(text)
        normalized = _normalize_unicode(clean)
        findings: list[DetectionFinding] = []

        for pattern, desc in self._critical:
            m = pattern.search(normalized)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.JAILBREAK,
                    severity=Severity.CRITICAL,
                    confidence=0.92,
                    description=desc,
                    matched_pattern=m.group()[:80],
                    position=m.start(),
                ))

        for pattern, desc in self._high:
            m = pattern.search(normalized)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.JAILBREAK,
                    severity=Severity.HIGH,
                    confidence=0.82,
                    description=desc,
                    matched_pattern=m.group()[:80],
                    position=m.start(),
                ))

        for pattern, desc in self._medium:
            m = pattern.search(normalized)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.JAILBREAK,
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    description=desc,
                    matched_pattern=m.group()[:80],
                    position=m.start(),
                ))

        # Many-shot jailbreak detection
        many_shot = _detect_many_shot(normalized)
        if many_shot:
            findings.append(many_shot)

        blocked = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        return DetectionResult(blocked=blocked, findings=findings)


# ── Many-shot jailbreak detection ─────────────────────────────────────
# Technique: provide 3+ examples of assistant complying with harmful requests
# before making the actual harmful request. Exploits in-context learning.

_MANYSHOT_USER_RE = re.compile(
    r"(?:User|Human|Q)\s*:.{5,300}?(?:Assistant|AI|A)\s*:\s*(?:Sure|Of course|Certainly|Yes|Happy to|Absolutely|Here'?s?)",
    re.IGNORECASE | re.DOTALL,
)

_MANYSHOT_HARMFUL_KEYWORDS = [
    "how to make", "how to build", "how to create", "step by step",
    "instructions for", "tutorial on", "guide to", "synthesize",
    "hack into", "bypass", "exploit", "illegal", "bomb", "weapon",
]


def _detect_many_shot(text: str) -> DetectionFinding | None:
    """
    Detect many-shot jailbreaking: 3+ compliant Q&A pairs before harmful request.
    This exploits in-context learning — showing the model "examples" of compliance.
    """
    matches = _MANYSHOT_USER_RE.findall(text)
    if len(matches) < 3:
        return None

    # Check if any harmful keywords appear in the conversation
    text_lower = text.lower()
    harmful_count = sum(1 for kw in _MANYSHOT_HARMFUL_KEYWORDS if kw in text_lower)

    if harmful_count >= 1 and len(matches) >= 3:
        return DetectionFinding(
            category=DetectionCategory.JAILBREAK,
            severity=Severity.HIGH,
            confidence=0.88,
            description=f"Many-shot jailbreak detected: {len(matches)} compliant Q&A examples with harmful keywords",
            matched_pattern=f"[{len(matches)} Q&A pairs, {harmful_count} harmful keywords]",
            position=0,
        )

    return None
