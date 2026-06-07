"""
Upstream error handling with retry logic.

Retry policy:
  429 (rate limit)   → wait 1s, retry once
  500/502/503        → retry once immediately
  timeout            → retry once with doubled timeout
  4xx (not 429)      → no retry, surface error to client
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import structlog

log = structlog.get_logger(__name__)

# Provider-specific timeout config (seconds)
_PROVIDER_TIMEOUTS: dict[str, httpx.Timeout] = {
    "openai":    httpx.Timeout(connect=10.0, read=90.0,  write=10.0, pool=5.0),
    "anthropic": httpx.Timeout(connect=10.0, read=90.0,  write=10.0, pool=5.0),
    "bedrock":   httpx.Timeout(connect=15.0, read=120.0, write=15.0, pool=5.0),
    "azure":     httpx.Timeout(connect=10.0, read=90.0,  write=10.0, pool=5.0),
    "gemini":    httpx.Timeout(connect=10.0, read=60.0,  write=10.0, pool=5.0),
    "groq":      httpx.Timeout(connect=5.0,  read=30.0,  write=5.0,  pool=5.0),
    "mistral":   httpx.Timeout(connect=10.0, read=60.0,  write=10.0, pool=5.0),
    "cohere":    httpx.Timeout(connect=10.0, read=60.0,  write=10.0, pool=5.0),
    "deepseek":  httpx.Timeout(connect=10.0, read=90.0,  write=10.0, pool=5.0),
    "ollama":    httpx.Timeout(connect=5.0,  read=120.0, write=10.0, pool=5.0),
}

_DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=5.0)


def get_timeout(provider: str) -> httpx.Timeout:
    return _PROVIDER_TIMEOUTS.get(provider, _DEFAULT_TIMEOUT)


def _openai_error(message: str, error_type: str = "upstream_error", status: int = 502) -> tuple[dict[str, Any], int]:
    return {
        "error": {
            "message": message,
            "type": error_type,
            "code": status,
        }
    }, status


async def request_with_retry(
    client: httpx.AsyncClient,
    provider: str,
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    max_retries: int = 1,
) -> tuple[dict[str, Any], int]:
    """
    POST with retry. Returns (response_dict, status_code).
    Never raises — always returns a structured error on failure.
    """
    timeout = get_timeout(provider)
    last_error: str = ""

    for attempt in range(max_retries + 1):
        try:
            r = await client.post(url, json=body, headers=headers, timeout=timeout)

            # Success
            if r.status_code < 400:
                try:
                    return r.json(), r.status_code
                except Exception:
                    return {"error": {"message": "Invalid JSON from upstream"}}, 502

            # 429 — rate limited
            if r.status_code == 429 and attempt < max_retries:
                retry_after = float(r.headers.get("retry-after", "1.0"))
                retry_after = min(retry_after, 5.0)  # cap at 5s
                log.warning("rate_limited", provider=provider, retry_after=retry_after, attempt=attempt)
                await asyncio.sleep(retry_after)
                continue

            # 5xx — server error, retry once
            if r.status_code >= 500 and attempt < max_retries:
                log.warning("upstream_5xx", provider=provider, status=r.status_code, attempt=attempt)
                await asyncio.sleep(0.5)
                continue

            # 4xx (not 429) — client error, no retry
            try:
                error_body = r.json()
            except Exception:
                error_body = {"error": {"message": r.text}}

            log.warning("upstream_4xx", provider=provider, status=r.status_code)
            return error_body, r.status_code

        except httpx.TimeoutException:
            last_error = f"Request to {provider} timed out after {timeout.read}s"
            if attempt < max_retries:
                log.warning("upstream_timeout_retrying", provider=provider, attempt=attempt)
                # Double the read timeout for retry
                timeout = httpx.Timeout(
                    connect=timeout.connect,
                    read=min(timeout.read * 1.5, 180.0),
                    write=timeout.write,
                    pool=timeout.pool,
                )
                continue

        except httpx.ConnectError:
            last_error = f"Cannot connect to {provider} API"
            if attempt < max_retries:
                await asyncio.sleep(1.0)
                continue

        except httpx.RequestError as e:
            last_error = str(e)

    log.error("upstream_failed", provider=provider, error=last_error)
    return _openai_error(last_error, "upstream_error", 502)
