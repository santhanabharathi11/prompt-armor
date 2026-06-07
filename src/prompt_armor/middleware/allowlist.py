"""
Allowlist / bypass mechanism for prompt-armor.

Allows pre-approved service accounts to bypass scanning for specific use cases
(e.g. a document generation service that intentionally sends PII, or a batch
analytics pipeline where all data is pre-screened).

Security model:
  - Bypass tokens are strong secrets configured in .env (never in code)
  - Every bypass is logged to audit trail — not invisible
  - Bypass does NOT disable rate limiting or auth
  - Two bypass modes:
    * full  — skip all detectors (service account with pre-screened data)
    * pii   — skip PII detector only (document generation use case)
    * injection — skip injection/jailbreak only (internal tools with trusted prompts)

Header: X-Armor-Bypass: <token>
"""

from __future__ import annotations

import hashlib
from typing import Literal

import structlog

log = structlog.get_logger(__name__)

BypassMode = Literal["full", "pii", "injection", "none"]


def _load_bypass_tokens() -> dict[str, BypassMode]:
    """Load bypass tokens from config. Format: TOKEN:MODE,TOKEN:MODE"""
    from ..config import settings

    tokens: dict[str, BypassMode] = {}
    raw = getattr(settings, "bypass_tokens", "")
    if not raw:
        return tokens

    for entry in raw.split(","):
        entry = entry.strip()
        if ":" in entry:
            token, mode = entry.split(":", 1)
            mode = mode.strip().lower()
            if mode in ("full", "pii", "injection"):
                tokens[token.strip()] = mode  # type: ignore[assignment]
        else:
            tokens[entry] = "full"

    return tokens


_BYPASS_TOKENS: dict[str, BypassMode] = {}
_LOADED = False


def _get_tokens() -> dict[str, BypassMode]:
    global _BYPASS_TOKENS, _LOADED
    if not _LOADED:
        _BYPASS_TOKENS = _load_bypass_tokens()
        _LOADED = True
    return _BYPASS_TOKENS


def check_bypass(bypass_header: str | None, request_id: str) -> BypassMode:
    """
    Check if X-Armor-Bypass header contains a valid bypass token.

    Returns:
        "full"      — skip all detectors
        "pii"       — skip PII detector only
        "injection" — skip injection + jailbreak only
        "none"      — no bypass (normal scanning)

    IMPORTANT: Every bypass is logged. Bypass is NOT invisible.
    """
    if not bypass_header:
        return "none"

    tokens = _get_tokens()
    mode = tokens.get(bypass_header.strip(), "none")

    if mode != "none":
        # Log bypass — security team must see this in audit
        token_hash = hashlib.sha256(bypass_header.encode()).hexdigest()[:12]
        log.warning(
            "scanning_bypassed",
            request_id=request_id,
            bypass_mode=mode,
            token_hash=token_hash,
            message="Scanning bypassed via allowlist token. Verify this is expected.",
        )

    return mode


def get_bypass_description(mode: BypassMode) -> str:
    descriptions = {
        "full": "All detectors bypassed (allowlisted service account)",
        "pii": "PII detector bypassed (allowlisted — document generation context)",
        "injection": "Injection/jailbreak detectors bypassed (allowlisted — trusted internal prompt)",
        "none": "",
    }
    return descriptions.get(mode, "")
