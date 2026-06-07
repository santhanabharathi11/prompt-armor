"""
Structured audit logger.

Every request gets a structured JSON log entry.
PII is hashed — raw PII never written to disk.
Logs are append-only JSONL, rotatable by logrotate.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import structlog

from ..models import DetectionFinding, Severity

log = structlog.get_logger(__name__)


def _hash_if_pii(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _severity_max(findings: list[DetectionFinding]) -> str:
    order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
    if not findings:
        return "none"
    return max(findings, key=lambda f: order.get(f.severity, 0)).severity.value


class AuditLogger:
    def __init__(self) -> None:
        from ..config import settings

        self.enabled = settings.audit_log_enabled
        self.log_path = Path(settings.audit_log_path)
        self._lock = asyncio.Lock()

        if self.enabled:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    async def log(
        self,
        request_id: str,
        provider: str,
        blocked: bool,
        findings: list[DetectionFinding],
        latency_ms: int,
    ) -> None:
        if not self.enabled:
            return

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "provider": provider,
            "blocked": blocked,
            "latency_ms": latency_ms,
            "max_severity": _severity_max(findings),
            "finding_count": len(findings),
            "findings": [
                {
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "confidence": round(f.confidence, 3),
                    "description": f.description,
                    # Never log the actual matched text — log a hash
                    "pattern_hash": _hash_if_pii(f.matched_pattern or ""),
                }
                for f in findings
            ],
        }

        # structlog for stdout (container logs, CloudWatch)
        log.info(
            "request_processed",
            request_id=request_id,
            provider=provider,
            blocked=blocked,
            finding_count=len(findings),
            latency_ms=latency_ms,
        )

        # JSONL file for persistent audit trail
        async with self._lock:
            try:
                with self.log_path.open("a") as f:
                    f.write(json.dumps(entry) + "\n")
            except OSError as e:
                log.error("audit_log_write_failed", error=str(e))
