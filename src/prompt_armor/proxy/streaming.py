"""
Streaming proxy handler — SSE passthrough with real-time scanning.

Strategy (enterprise-safe):
  INPUT:  Scan synchronously before forwarding. Block if found. <5ms overhead.
  OUTPUT: Forward chunks in real-time for low latency. Scan accumulated text
          at stream end. Log PII findings. Cannot un-send streamed chunks,
          so output scanning is warn + log only (industry standard).

Supported SSE formats:
  OpenAI-compat  → OpenAI, Groq, Mistral, DeepSeek (data: JSON\n\n)
  Anthropic      → event: + data: pairs
  Gemini         → data: JSON\n\n (similar to OpenAI)
  Cohere         → data: JSON\n\n (v2 streaming)
  Bedrock        → event stream (handled via boto3 separately)
"""

from __future__ import annotations

import json
from typing import Any, AsyncGenerator

import httpx
import structlog

from ..config import settings
from ..models import ArmorError, DetectionResult

log = structlog.get_logger(__name__)

# Chunk size for reading upstream SSE
_CHUNK_SIZE = 1024


def _sse_error(result: DetectionResult, request_id: str) -> bytes:
    """Return a well-formed SSE error that closes the stream."""
    error = ArmorError.from_result(result, request_id)
    payload = json.dumps(error.model_dump())
    return f"data: {payload}\n\ndata: [DONE]\n\n".encode()


def _extract_text_from_chunk(chunk_data: str, provider: str) -> str:
    """Pull generated text out of a single SSE chunk across provider formats."""
    try:
        data = json.loads(chunk_data)
    except json.JSONDecodeError:
        return ""

    if provider in ("openai", "groq", "mistral", "deepseek", "azure"):
        # OpenAI delta format
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("delta", {}).get("content", "") or ""

    elif provider == "anthropic":
        # Anthropic content_block_delta
        if data.get("type") == "content_block_delta":
            return data.get("delta", {}).get("text", "") or ""

    elif provider == "gemini":
        # Gemini candidates format
        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            return "".join(p.get("text", "") for p in parts)

    elif provider == "cohere":
        # Cohere v2 streaming
        if data.get("type") == "content-delta":
            return data.get("delta", {}).get("message", {}).get("content", {}).get("text", "") or ""

    return ""


def _extract_usage_from_chunk(chunk_data: str, provider: str) -> dict[str, int]:
    """Extract token usage from final chunk if present."""
    try:
        data = json.loads(chunk_data)
    except json.JSONDecodeError:
        return {}

    if provider in ("openai", "groq", "mistral", "deepseek", "azure"):
        usage = data.get("usage", {})
        return {
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
        }
    elif provider == "anthropic":
        if data.get("type") == "message_delta":
            usage = data.get("usage", {})
            return {"output_tokens": usage.get("output_tokens", 0)}
        if data.get("type") == "message_start":
            usage = data.get("message", {}).get("usage", {})
            return {"input_tokens": usage.get("input_tokens", 0)}

    return {}


class StreamingProxy:
    """
    Handles streaming requests for all providers.
    Used by ProxyRouter when body contains stream=true.
    """

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def stream(
        self,
        provider: str,
        path: str,
        body: dict[str, Any],
        request_id: str,
        input_blocked_result: DetectionResult | None,
        pii_detector: Any,
        stats: Any,
    ) -> AsyncGenerator[bytes, None]:
        """
        Main streaming generator. Yields SSE bytes.

        If input was blocked, yields a single error SSE and returns.
        Otherwise streams from upstream and scans output at end.
        """
        if input_blocked_result and input_blocked_result.blocked:
            yield _sse_error(input_blocked_result, request_id)
            return

        upstream_url, upstream_headers = self._build_request(provider, path, body)

        accumulated_text = ""
        usage: dict[str, int] = {}

        try:
            async with self._client.stream(
                "POST",
                upstream_url,
                json=body,
                headers=upstream_headers,
                timeout=httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=5.0),
            ) as response:

                if response.status_code != 200:
                    error_body = await response.aread()
                    try:
                        error_json = json.loads(error_body)
                    except json.JSONDecodeError:
                        error_json = {"error": {"message": error_body.decode()}}
                    yield f"data: {json.dumps(error_json)}\n\ndata: [DONE]\n\n".encode()
                    return

                async for line in response.aiter_lines():
                    if not line:
                        yield b"\n"
                        continue

                    # Forward raw SSE line immediately — low latency
                    yield (line + "\n").encode()

                    # Parse for text accumulation and usage extraction
                    if line.startswith("data: ") and line != "data: [DONE]":
                        chunk_data = line[6:]
                        text = _extract_text_from_chunk(chunk_data, provider)
                        if text:
                            accumulated_text += text
                        chunk_usage = _extract_usage_from_chunk(chunk_data, provider)
                        if chunk_usage:
                            usage.update(chunk_usage)

                    elif line.startswith("data: [DONE]"):
                        break

        except httpx.TimeoutException:
            error = json.dumps({"error": {"message": "Upstream timeout", "type": "timeout"}})
            yield f"data: {error}\n\ndata: [DONE]\n\n".encode()
            log.warning("streaming_timeout", provider=provider, request_id=request_id)
            return
        except httpx.RequestError as e:
            error = json.dumps({"error": {"message": str(e), "type": "upstream_error"}})
            yield f"data: {error}\n\ndata: [DONE]\n\n".encode()
            log.error("streaming_error", provider=provider, error=str(e))
            return

        # ── Output scan at stream end ──────────────────────────────────
        if accumulated_text and pii_detector:
            output_result = pii_detector.scan(accumulated_text, context="output")
            if output_result.findings:
                log.warning(
                    "output_pii_detected_in_stream",
                    request_id=request_id,
                    finding_count=len(output_result.findings),
                    note="Cannot redact already-streamed content. Logged for audit.",
                )

        # Update stats with token usage
        if stats and usage:
            await stats.record_tokens(
                provider=provider,
                input_tokens=usage.get("input_tokens", 0),
                output_tokens=usage.get("output_tokens", 0),
            )

    def _build_request(
        self, provider: str, path: str, body: dict[str, Any]
    ) -> tuple[str, dict[str, str]]:
        """Return (url, headers) for upstream streaming request."""

        if provider == "openai":
            return (
                f"https://api.openai.com{path}",
                {"Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"},
            )
        elif provider == "anthropic":
            return (
                f"https://api.anthropic.com{path}",
                {
                    "x-api-key": settings.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
            )
        elif provider == "azure":
            url = f"{settings.azure_openai_endpoint.rstrip('/')}{path}"
            if "api-version" not in url:
                url += f"?api-version={settings.azure_openai_api_version}"
            return (url, {"api-key": settings.azure_openai_api_key, "Content-Type": "application/json"})
        elif provider == "groq":
            return (
                f"https://api.groq.com/openai{path}",
                {"Authorization": f"Bearer {settings.groq_api_key}", "Content-Type": "application/json"},
            )
        elif provider == "mistral":
            return (
                f"https://api.mistral.ai{path}",
                {"Authorization": f"Bearer {settings.mistral_api_key}", "Content-Type": "application/json"},
            )
        elif provider == "deepseek":
            return (
                f"https://api.deepseek.com{path}",
                {"Authorization": f"Bearer {settings.deepseek_api_key}", "Content-Type": "application/json"},
            )
        elif provider == "gemini":
            model = body.get("model", "gemini-2.0-flash").replace("google/", "").replace("gemini/", "")
            return (
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent?key={settings.gemini_api_key}&alt=sse",
                {"Content-Type": "application/json"},
            )
        elif provider == "ollama":
            return (
                f"{settings.ollama_base_url.rstrip('/')}{path}",
                {"Content-Type": "application/json"},
            )
        else:
            raise ValueError(f"Streaming not supported for provider: {provider}")
