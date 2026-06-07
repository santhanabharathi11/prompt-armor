"""
Toxic content detector.

Catches requests for:
  - Harmful instructions (weapons, drugs, self-harm)
  - Hate speech signals
  - CSAM indicators (immediate block)
  - Doxxing / targeting individuals

This is a keyword-level first pass — not a replacement for a full content
moderation model. Pair with OpenAI Moderation API or AWS Comprehend in
production for higher recall.
"""

from __future__ import annotations

import re

from ..models import DetectionCategory, DetectionFinding, DetectionResult, Severity

# CSAM — always block, zero tolerance
_CSAM_PATTERNS: list[str] = [
    r"\bCSAM\b",
    r"child\s+(sexual|pornograph|nude|naked|exploit)",
    r"(underage|minor|child|kid|toddler|infant)\s+(sex|porn|nude|naked|explicit)",
    r"(sexual|explicit)\s+(content|material|image)\s+(of|involving|with)\s+(minor|child|underage)",
]

_CRITICAL_PATTERNS: list[tuple[str, str]] = [
    # Weapons of mass destruction
    (r"(how\s+to\s+)?(make|create|build|synthesize|manufacture)\s+(a\s+)?(biological|chemical|nuclear|radiological)\s+(weapon|bomb|agent)", "WMD instruction request"),
    (r"(how\s+to\s+)?(make|create|build|synthesize)\s+(sarin|VX\s+nerve|mustard\s+gas|ricin|anthrax)", "Chemical/biological weapon request"),
    (r"(how\s+to\s+)?(enrich|weaponize)\s+(uranium|plutonium)", "Nuclear material request"),

    # Explosive devices
    (r"(how\s+to\s+)?(make|build|construct|assemble)\s+(a\s+)?(bomb|IED|explosive\s+device|pipe\s+bomb)", "Explosive device instructions"),
    (r"TATP|PETN|RDX|C-4\s+explosive|ammonium\s+nitrate\s+(bomb|explosive)", "Explosive compound reference"),

    # Self-harm / suicide methods
    (r"(best|most\s+effective|painless|quickest)\s+(way|method|means)\s+to\s+(kill\s+myself|commit\s+suicide|end\s+my\s+life)", "Self-harm method request"),
    (r"(step\s+by\s+step|detailed)\s+(instructions?|guide|method)\s+(for|to)\s+(suicide|self-harm)", "Self-harm instruction request"),
]

_HIGH_PATTERNS: list[tuple[str, str]] = [
    # Drug synthesis
    (r"(how\s+to\s+)?(synthesize|make|cook|produce|manufacture)\s+(methamphetamine|meth|fentanyl|heroin|cocaine|LSD|MDMA)", "Drug synthesis request"),
    (r"(drug\s+synthesis|clandestine\s+lab|one-pot\s+meth)", "Drug synthesis reference"),

    # Hacking / cyberattack tools
    (r"(write|create|build|code)\s+(me\s+)?(a\s+)?(ransomware|keylogger|rootkit|RAT\s+(tool|trojan)|botnet)", "Malware creation request"),
    (r"(how\s+to\s+)?(hack|compromise)\s+into\s+(someone('s)?|a\s+person's|my\s+[\w\-]+'s?)", "Targeted attack request"),
    (r"break\s+into\s+(someone('s)?|a\s+person's|my\s+[\w\-]+'s?)", "Targeted attack request"),
    (r"(exploit|payload)\s+(for|targeting)\s+(CVE-\d{4}-\d+)", "Exploit code request"),

    # Hate speech
    (r"(all|every|most)\s+(jews?|muslims?|christians?|hindus?|blacks?|whites?|asians?)\s+(are|should\s+be|deserve\s+to\s+be|should\s+die)", "Hate speech pattern"),

    # Doxxing / targeting individuals
    (r"(find|get|locate)\s+(the\s+)?(home\s+address|personal\s+details|private\s+information)\s+(of|for|about)\s+", "Doxxing request"),
    (r"(stalk|track|follow|surveil)\s+(someone|a\s+person|my\s+ex|him|her)\s+(without|covertly|secretly)", "Stalking facilitation"),
]

_MEDIUM_PATTERNS: list[tuple[str, str]] = [
    (r"(how\s+to\s+)?(get|obtain|buy|acquire)\s+(illegal\s+)?(guns?|firearms?|weapons?)\s+(illegally|without\s+(background\s+check|license|permit))", "Illegal weapons acquisition"),
    (r"(how\s+to\s+)?(shoplift|steal|rob|pickpocket)\s+without\s+(getting\s+caught|detection)", "Theft facilitation"),
    (r"(how\s+to\s+)?(launder|wash)\s+(money|funds|cash)", "Money laundering request"),
    (r"(create|forge|fake)\s+(id(entification)?|passport|driver'?s?\s+license|document)", "Document forgery request"),
]


class ToxicDetector:
    def __init__(self) -> None:
        self._csam = [re.compile(p, re.IGNORECASE) for p in _CSAM_PATTERNS]
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
        findings: list[DetectionFinding] = []

        # CSAM — zero tolerance, always block
        for pattern in self._csam:
            m = pattern.search(text)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.TOXIC,
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    description="CSAM indicator — zero tolerance block",
                    matched_pattern="[REDACTED]",
                    position=m.start(),
                ))
                return DetectionResult(blocked=True, findings=findings)

        for pattern, desc in self._critical:
            m = pattern.search(text)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.TOXIC,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    description=desc,
                    matched_pattern=m.group()[:80],
                    position=m.start(),
                ))

        for pattern, desc in self._high:
            m = pattern.search(text)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.TOXIC,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    description=desc,
                    matched_pattern=m.group()[:80],
                    position=m.start(),
                ))

        for pattern, desc in self._medium:
            m = pattern.search(text)
            if m:
                findings.append(DetectionFinding(
                    category=DetectionCategory.TOXIC,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    description=desc,
                    matched_pattern=m.group()[:80],
                    position=m.start(),
                ))

        blocked = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        return DetectionResult(blocked=blocked, findings=findings)
