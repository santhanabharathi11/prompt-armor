"""
Token bucket rate limiter backed by Redis.
Falls back to in-memory (single process) if Redis is unavailable.
"""

from __future__ import annotations

import time
from collections import defaultdict

import structlog

log = structlog.get_logger(__name__)


class InMemoryBucket:
    """Single-process fallback — not suitable for multi-worker deployments."""

    def __init__(self, requests_per_minute: int) -> None:
        self.rpm = requests_per_minute
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        window_start = now - 60
        self._buckets[key] = [t for t in self._buckets[key] if t > window_start]
        if len(self._buckets[key]) >= self.rpm:
            return False
        self._buckets[key].append(now)
        return True


class RateLimiter:
    def __init__(self) -> None:
        from ..config import settings

        self.enabled = settings.rate_limit_enabled
        self.rpm = settings.rate_limit_requests
        self._redis: object | None = None
        self._fallback = InMemoryBucket(self.rpm)

        if self.enabled:
            try:
                import redis

                self._redis = redis.from_url(settings.redis_url, decode_responses=True)
                self._redis.ping()  # type: ignore[union-attr]
                log.info("rate_limiter_redis_connected")
            except Exception as e:
                log.warning("rate_limiter_redis_unavailable", error=str(e), fallback="in_memory")
                self._redis = None

    def is_allowed(self, client_ip: str) -> bool:
        if not self.enabled:
            return True

        key = f"armor:rl:{client_ip}"

        if self._redis:
            try:
                pipe = self._redis.pipeline()  # type: ignore[union-attr]
                now = int(time.time() * 1000)
                window_ms = 60_000
                pipe.zremrangebyscore(key, 0, now - window_ms)
                pipe.zadd(key, {str(now): now})
                pipe.zcard(key)
                pipe.expire(key, 120)
                results = pipe.execute()
                count = results[2]
                return int(count) <= self.rpm
            except Exception as e:
                log.warning("rate_limiter_redis_error", error=str(e))
                return self._fallback.is_allowed(client_ip)

        return self._fallback.is_allowed(client_ip)
