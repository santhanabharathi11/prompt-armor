# Architecture

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         YOUR APPLICATION                             │
│                                                                       │
│   openai.OpenAI(base_url="http://localhost:8000/openai")             │
└───────────────────────────────┬─────────────────────────────────────┘
                                │  HTTP POST /openai/v1/chat/completions
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         PROMPT-ARMOR PROXY                           │
│                                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │  Rate        │  │  Auth        │  │  Token       │               │
│  │  Limiter     │  │  Check       │  │  Limit Guard │               │
│  │  (Redis)     │  │  (API Key)   │  │  (tiktoken)  │               │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
│         └─────────────────┴─────────────────┘                       │
│                                │                                      │
│                                ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │                    INPUT SCAN PIPELINE                        │    │
│  │                                                               │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │    │
│  │  │  Injection   │  │  Jailbreak   │  │    PII       │       │    │
│  │  │  Detector    │  │  Detector    │  │  Detector    │       │    │
│  │  │              │  │              │  │  (In/Out)    │       │    │
│  │  │ • Overrides  │  │ • DAN/STAN   │  │ • Aadhaar    │       │    │
│  │  │ • Delimiter  │  │ • Dev Mode   │  │ • PAN / IFSC │       │    │
│  │  │ • Tokens     │  │ • Personas   │  │ • Credit Card│       │    │
│  │  │ • Base64     │  │ • Unicode    │  │ • Email/Phone│       │    │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │    │
│  │         │                  │                  │               │    │
│  │  ┌──────┴──────────────────┴──────────────────┴───────┐      │    │
│  │  │              Toxic Detector                          │      │    │
│  │  │  • WMD / Explosives  • Drug synthesis               │      │    │
│  │  │  • CSAM (zero tol.)  • Malware creation             │      │    │
│  │  │  • Doxxing / Stalk   • Hate speech                  │      │    │
│  │  └──────────────────────────────────────────────────────┘      │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                │                                      │
│                    ┌───────────┴───────────┐                         │
│                    │                       │                         │
│              BLOCKED (400)           ALLOWED → FORWARD               │
│                    │                       │                         │
│                    ▼                       ▼                         │
│  ┌─────────────────────┐   ┌──────────────────────────────────┐     │
│  │   ArmorError        │   │        PROVIDER ROUTER            │     │
│  │  (OpenAI-compat     │   │                                   │     │
│  │   error format)     │   │  /openai  → api.openai.com        │     │
│  └─────────────────────┘   │  /anthropic → api.anthropic.com  │     │
│                             │  /bedrock  → AWS Bedrock boto3   │     │
│                             │  /azure   → Azure OAI endpoint   │     │
│                             │  /ollama  → localhost:11434      │     │
│                             └────────────────┬─────────────────┘     │
│                                              │                        │
│                                     LLM response                     │
│                                              │                        │
│                                              ▼                        │
│                          ┌────────────────────────────────┐          │
│                          │      OUTPUT SCAN PIPELINE       │          │
│                          │  PII scan → mask if configured  │          │
│                          └────────────────────────────────┘          │
│                                              │                        │
│  ┌─────────────────────────────────────┐    │                        │
│  │         AUDIT LOGGER                │◄───┘                        │
│  │  • Structured JSON (stdout)         │                             │
│  │  • JSONL file (append-only)         │                             │
│  │  • PII hashed — never raw           │                             │
│  │  • request_id, latency, findings    │                             │
│  └─────────────────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────┘
                                │
                    Response returned to your app
```

## Detection Pipeline Detail

### Injection Detector
Scans every user message against 25+ patterns across three severity tiers:

| Severity | Examples | Action |
|----------|----------|--------|
| CRITICAL | `ignore previous instructions`, training tokens `<\|im_start\|>`, base64 payloads | Block |
| HIGH | Persona hijacking (`you are now`), system prompt extraction, goal override | Block |
| MEDIUM | Indirect probes, delayed injection signals | Log/Warn |

### Jailbreak Detector
Unicode normalization before scanning — defeats Cyrillic/Greek character substitution.

| Technique | Example | Detected |
|-----------|---------|----------|
| DAN variants | `do anything now`, `JAILBREAK` | ✓ |
| Developer mode | `enable developer mode` | ✓ |
| Safety bypass | `respond without restrictions` | ✓ |
| Grandma exploit | `my grandmother used to tell me how to make...` | ✓ |
| Fiction framing | `write a story where a character explains how to...` | ✓ |
| Token manipulation | Spaced characters `j a i l b r e a k` | ✓ |

### PII Detector
Regex-based with Luhn validation for cards. Covers Indian + international PII.

| Type | Pattern | Validator |
|------|---------|-----------|
| Aadhaar | `2-9XXX XXXX XXXX` | Length + first digit check |
| PAN | `ABCDE1234F` | Format regex |
| IFSC | `HDFC0001234` | Format regex |
| Credit Card | Visa/MC/Amex | Luhn algorithm |
| SSN | `XXX-XX-XXXX` | Format regex |
| Email | RFC 5322 subset | Format regex |

### Toxic Detector
Zero tolerance for CSAM — instant block, no further processing.
Covers WMD, drug synthesis, malware creation, doxxing, hate speech.

## Deployment Modes

### 1. Docker (Recommended)
```bash
docker compose -f docker/docker-compose.yml up -d
```

### 2. Kubernetes Sidecar
```yaml
# Add as sidecar to your LLM-calling pod
containers:
  - name: prompt-armor
    image: prompt-armor:latest
    ports: [{containerPort: 8000}]
    envFrom: [{secretRef: {name: prompt-armor-secrets}}]
```

### 3. Python Library (Inline)
```python
from prompt_armor.detectors import InjectionDetector, PIIDetector

detector = InjectionDetector()
result = detector.scan(user_input)
if result.blocked:
    raise ValueError("Input blocked by security policy")
```

## Audit Log Format

Every request produces one JSONL line (never contains raw PII):

```json
{
  "ts": "2026-06-07T10:30:00.123Z",
  "request_id": "a3f2c1d4-...",
  "provider": "openai",
  "blocked": false,
  "latency_ms": 847,
  "max_severity": "medium",
  "finding_count": 1,
  "findings": [
    {
      "category": "pii_input",
      "severity": "medium",
      "confidence": 0.9,
      "description": "Email detected in input",
      "pattern_hash": "a3f2c1d4e5b6f7a8"
    }
  ]
}
```
