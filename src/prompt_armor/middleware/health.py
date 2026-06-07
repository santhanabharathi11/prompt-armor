"""
Provider health checker.
Sends a minimal request to each configured provider and reports status.
Does NOT send any real content — uses provider test endpoints or
a trivially short prompt with max_tokens=1.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog

from ..config import settings

log = structlog.get_logger(__name__)

_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=2.0)


async def _check_openai(client: httpx.AsyncClient) -> dict[str, Any]:
    if not settings.openai_api_key:
        return {"status": "unconfigured"}
    t = time.perf_counter()
    try:
        r = await client.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {settings.openai_api_key}"},
            timeout=_TIMEOUT,
        )
        latency = int((time.perf_counter() - t) * 1000)
        return {"status": "ok" if r.status_code == 200 else "error", "latency_ms": latency, "http": r.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


async def _check_anthropic(client: httpx.AsyncClient) -> dict[str, Any]:
    if not settings.anthropic_api_key:
        return {"status": "unconfigured"}
    t = time.perf_counter()
    try:
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": settings.anthropic_api_key, "anthropic-version": "2023-06-01"},
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]},
            timeout=_TIMEOUT,
        )
        latency = int((time.perf_counter() - t) * 1000)
        # 200 = ok, 400 = api key works but bad request = still ok
        ok = r.status_code in (200, 400)
        return {"status": "ok" if ok else "error", "latency_ms": latency, "http": r.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


async def _check_groq(client: httpx.AsyncClient) -> dict[str, Any]:
    if not settings.groq_api_key:
        return {"status": "unconfigured"}
    t = time.perf_counter()
    try:
        r = await client.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {settings.groq_api_key}"},
            timeout=_TIMEOUT,
        )
        latency = int((time.perf_counter() - t) * 1000)
        return {"status": "ok" if r.status_code == 200 else "error", "latency_ms": latency, "http": r.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


async def _check_mistral(client: httpx.AsyncClient) -> dict[str, Any]:
    if not settings.mistral_api_key:
        return {"status": "unconfigured"}
    t = time.perf_counter()
    try:
        r = await client.get(
            "https://api.mistral.ai/v1/models",
            headers={"Authorization": f"Bearer {settings.mistral_api_key}"},
            timeout=_TIMEOUT,
        )
        latency = int((time.perf_counter() - t) * 1000)
        return {"status": "ok" if r.status_code == 200 else "error", "latency_ms": latency, "http": r.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


async def _check_gemini(client: httpx.AsyncClient) -> dict[str, Any]:
    if not settings.gemini_api_key:
        return {"status": "unconfigured"}
    t = time.perf_counter()
    try:
        r = await client.get(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={settings.gemini_api_key}",
            timeout=_TIMEOUT,
        )
        latency = int((time.perf_counter() - t) * 1000)
        return {"status": "ok" if r.status_code == 200 else "error", "latency_ms": latency, "http": r.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


async def _check_deepseek(client: httpx.AsyncClient) -> dict[str, Any]:
    if not settings.deepseek_api_key:
        return {"status": "unconfigured"}
    t = time.perf_counter()
    try:
        r = await client.get(
            "https://api.deepseek.com/models",
            headers={"Authorization": f"Bearer {settings.deepseek_api_key}"},
            timeout=_TIMEOUT,
        )
        latency = int((time.perf_counter() - t) * 1000)
        return {"status": "ok" if r.status_code == 200 else "error", "latency_ms": latency, "http": r.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


async def _check_ollama(client: httpx.AsyncClient) -> dict[str, Any]:
    t = time.perf_counter()
    try:
        r = await client.get(f"{settings.ollama_base_url}/api/tags", timeout=_TIMEOUT)
        latency = int((time.perf_counter() - t) * 1000)
        return {"status": "ok" if r.status_code == 200 else "error", "latency_ms": latency, "http": r.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


async def _check_azure(client: httpx.AsyncClient) -> dict[str, Any]:
    if not settings.azure_openai_api_key or not settings.azure_openai_endpoint:
        return {"status": "unconfigured"}
    t = time.perf_counter()
    try:
        r = await client.get(
            f"{settings.azure_openai_endpoint.rstrip('/')}/openai/models?api-version={settings.azure_openai_api_version}",
            headers={"api-key": settings.azure_openai_api_key},
            timeout=_TIMEOUT,
        )
        latency = int((time.perf_counter() - t) * 1000)
        return {"status": "ok" if r.status_code == 200 else "error", "latency_ms": latency, "http": r.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


async def _check_bedrock() -> dict[str, Any]:
    try:
        import boto3
        t = time.perf_counter()
        client = boto3.client("bedrock", region_name=settings.aws_region)
        client.list_foundation_models(byOutputModality="TEXT")
        latency = int((time.perf_counter() - t) * 1000)
        return {"status": "ok", "latency_ms": latency}
    except Exception as e:
        err = str(e)[:80]
        if "NoCredentialsError" in err or "Unable to locate credentials" in err:
            return {"status": "unconfigured"}
        return {"status": "error", "error": err}


async def _check_cohere(client: httpx.AsyncClient) -> dict[str, Any]:
    if not settings.cohere_api_key:
        return {"status": "unconfigured"}
    t = time.perf_counter()
    try:
        r = await client.get(
            "https://api.cohere.com/v2/models",
            headers={"Authorization": f"Bearer {settings.cohere_api_key}"},
            timeout=_TIMEOUT,
        )
        latency = int((time.perf_counter() - t) * 1000)
        return {"status": "ok" if r.status_code == 200 else "error", "latency_ms": latency, "http": r.status_code}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)[:80]}


async def check_all_providers() -> dict[str, Any]:
    """Run all provider health checks concurrently. Returns in ~5s max."""
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            _check_openai(client),
            _check_anthropic(client),
            _check_groq(client),
            _check_mistral(client),
            _check_gemini(client),
            _check_deepseek(client),
            _check_ollama(client),
            _check_azure(client),
            _check_cohere(client),
            asyncio.to_thread(_check_bedrock),
            return_exceptions=True,
        )

    providers = ["openai", "anthropic", "groq", "mistral", "gemini",
                 "deepseek", "ollama", "azure", "cohere", "bedrock"]

    health: dict[str, Any] = {}
    for name, result in zip(providers, results):
        if isinstance(result, Exception):
            health[name] = {"status": "error", "error": str(result)[:80]}
        elif asyncio.iscoroutine(result):
            health[name] = await result
        else:
            health[name] = result

    configured = sum(1 for v in health.values() if v.get("status") != "unconfigured")
    healthy = sum(1 for v in health.values() if v.get("status") == "ok")

    return {
        "providers": health,
        "summary": {
            "configured": configured,
            "healthy": healthy,
            "total": len(providers),
        },
    }
