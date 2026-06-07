"""
Redis-backed stats — works correctly across multiple workers and replicas.
Uses atomic HINCRBY so counts are accurate under high concurrency.

Keys:
  armor:stats:requests:{provider}      → total requests
  armor:stats:blocked:{detector}       → blocks per detector
  armor:stats:tokens:{provider}:input  → input tokens
  armor:stats:tokens:{provider}:output → output tokens
  armor:stats:errors:{provider}        → upstream errors
  armor:stats:latency:{provider}       → sum of latency ms (divide by requests for avg)
"""

from __future__ import annotations

import json
import time
from typing import Any

import structlog

log = structlog.get_logger(__name__)

_STATS_TTL = 86400 * 7  # 7 days


class StatsCollector:
    def __init__(self) -> None:
        self._redis: Any = None
        self._fallback: dict[str, int] = {}
        self._connect()

    def _connect(self) -> None:
        from ..config import settings
        try:
            import redis
            self._redis = redis.from_url(settings.redis_url, decode_responses=True)
            self._redis.ping()
        except Exception as e:
            log.warning("stats_redis_unavailable", error=str(e), fallback="in_memory")
            self._redis = None

    def _incr(self, key: str, amount: int = 1) -> None:
        if self._redis:
            try:
                pipe = self._redis.pipeline()
                pipe.incrby(key, amount)
                pipe.expire(key, _STATS_TTL)
                pipe.execute()
                return
            except Exception:
                pass
        self._fallback[key] = self._fallback.get(key, 0) + amount

    def _get(self, key: str) -> int:
        if self._redis:
            try:
                v = self._redis.get(key)
                return int(v) if v else 0
            except Exception:
                pass
        return self._fallback.get(key, 0)

    def _get_all_keys(self, pattern: str) -> dict[str, int]:
        if self._redis:
            try:
                keys = self._redis.keys(pattern)
                if not keys:
                    return {}
                values = self._redis.mget(keys)
                return {k.split(":")[-1]: int(v or 0) for k, v in zip(keys, values)}
            except Exception:
                pass
        return {
            k.split(":")[-1]: v
            for k, v in self._fallback.items()
            if k.startswith(pattern.rstrip("*"))
        }

    async def record_request(
        self,
        provider: str,
        blocked: bool,
        latency_ms: int,
        detector_findings: dict[str, int],
    ) -> None:
        self._incr(f"armor:stats:requests:{provider}")
        self._incr(f"armor:stats:latency:{provider}", latency_ms)
        if blocked:
            self._incr(f"armor:stats:blocked_total:{provider}")
        for detector, count in detector_findings.items():
            if count:
                self._incr(f"armor:stats:findings:{detector}", count)

    async def record_tokens(
        self, provider: str, input_tokens: int, output_tokens: int
    ) -> None:
        if input_tokens:
            self._incr(f"armor:stats:tokens:{provider}:input", input_tokens)
        if output_tokens:
            self._incr(f"armor:stats:tokens:{provider}:output", output_tokens)

    async def record_error(self, provider: str) -> None:
        self._incr(f"armor:stats:errors:{provider}")

    def get_summary(self) -> dict[str, Any]:
        providers = [
            "openai", "anthropic", "bedrock", "azure", "ollama",
            "gemini", "groq", "mistral", "cohere", "deepseek",
        ]

        provider_stats = []
        total_requests = 0
        total_blocked = 0

        for p in providers:
            req = self._get(f"armor:stats:requests:{p}")
            if req == 0:
                continue
            blocked = self._get(f"armor:stats:blocked_total:{p}")
            latency_sum = self._get(f"armor:stats:latency:{p}")
            errors = self._get(f"armor:stats:errors:{p}")
            input_tok = self._get(f"armor:stats:tokens:{p}:input")
            output_tok = self._get(f"armor:stats:tokens:{p}:output")

            total_requests += req
            total_blocked += blocked

            provider_stats.append({
                "provider": p,
                "requests": req,
                "blocked": blocked,
                "block_rate_pct": round(blocked / req * 100, 1) if req else 0,
                "avg_latency_ms": round(latency_sum / req) if req else 0,
                "errors": errors,
                "tokens": {
                    "input": input_tok,
                    "output": output_tok,
                    "total": input_tok + output_tok,
                },
            })

        # Detection findings breakdown
        findings: dict[str, int] = {}
        if self._redis:
            try:
                keys = self._redis.keys("armor:stats:findings:*")
                for k in keys:
                    detector = k.split(":")[-1]
                    findings[detector] = int(self._redis.get(k) or 0)
            except Exception:
                pass
        else:
            for k, v in self._fallback.items():
                if "armor:stats:findings:" in k:
                    findings[k.split(":")[-1]] = v

        return {
            "summary": {
                "total_requests": total_requests,
                "total_blocked": total_blocked,
                "overall_block_rate_pct": (
                    round(total_blocked / total_requests * 100, 1) if total_requests else 0
                ),
            },
            "by_provider": provider_stats,
            "findings_by_detector": findings,
            "note": "Counters reset on restart if Redis unavailable",
        }
