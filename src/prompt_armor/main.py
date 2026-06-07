"""
prompt-armor — FastAPI entry point.

10 providers. Streaming + non-streaming. Security scanning on all paths.
Designed for 500-600 engineer teams: async, connection-pooled, Redis-backed.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from .config import settings
from .middleware.allowlist import check_bypass
from .middleware.rate_limiter import RateLimiter
from .middleware.stats import StatsCollector
from .proxy.router import ProxyRouter
from .proxy.streaming import StreamingProxy

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.JSONRenderer(),
    ]
)

log = structlog.get_logger(__name__)

_router: ProxyRouter | None = None
_rate_limiter: RateLimiter | None = None
_stats: StatsCollector | None = None
_streamer: StreamingProxy | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _router, _rate_limiter, _stats, _streamer
    log.info("prompt_armor_starting", version="0.1.0", port=settings.port)
    _router = ProxyRouter()
    _rate_limiter = RateLimiter()
    _stats = StatsCollector()
    _streamer = StreamingProxy(_router._client)
    yield
    log.info("prompt_armor_stopped")


app = FastAPI(
    title="prompt-armor",
    description="Self-hosted LLM firewall proxy. 10 providers. Streaming. Enterprise-grade security scanning.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


# ── Auth + rate limit ─────────────────────────────────────────────────

def _verify_auth(request: Request) -> None:
    if not settings.api_key:
        return
    auth = request.headers.get("Authorization", "")
    key = auth.removeprefix("Bearer ").strip()
    if key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _check_rate_limit(request: Request) -> None:
    if not _rate_limiter:
        return
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limiter.is_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again in 60 seconds.")


# ── Health / Meta ─────────────────────────────────────────────────────

@app.get("/health", tags=["Meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


@app.get("/", tags=["Meta"])
async def root() -> dict[str, Any]:
    return {
        "name": "prompt-armor",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health",
        "scan": "/scan",
        "stats": "/stats",
        "providers_health": "/providers/health",
        "providers": [
            "openai", "anthropic", "bedrock", "azure", "ollama",
            "gemini", "groq", "mistral", "cohere", "deepseek",
        ],
    }


@app.get("/stats", tags=["Observability"])
async def get_stats() -> dict[str, Any]:
    """Per-provider request counts, block rates, token usage. Redis-backed — accurate across workers."""
    if not _stats:
        raise HTTPException(status_code=503, detail="Stats not initialized")
    summary = _stats.get_summary()
    if settings.demo_mode and summary["summary"]["total_requests"] == 0:
        summary = _demo_stats()
    return summary


@app.get("/providers/health", tags=["Observability"])
async def providers_health() -> dict[str, Any]:
    """Check connectivity to all configured providers. Runs concurrently — completes in ~5s."""
    from .middleware.health import check_all_providers
    return await check_all_providers()


# ── Core proxy handler ────────────────────────────────────────────────

async def _proxy_request(request: Request, provider: str, path: str) -> Any:
    _verify_auth(request)
    _check_rate_limit(request)
    request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())

    # Check allowlist bypass BEFORE scanning
    bypass_header = request.headers.get("X-Armor-Bypass")
    bypass_mode = check_bypass(bypass_header, request_id)

    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Token limit guard (best-effort — no hard block if tiktoken missing)
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        text_content = " ".join(
            str(v) for v in body.values() if isinstance(v, str)
        )
        token_count = len(enc.encode(text_content))
        if token_count > settings.max_input_tokens:
            raise HTTPException(
                status_code=400,
                detail=f"Input exceeds {settings.max_input_tokens} token limit ({token_count} tokens)",
            )
    except ImportError:
        pass

    # ── Streaming path ────────────────────────────────────────────────
    if body.get("stream") is True:
        if not _streamer or not _router:
            raise HTTPException(status_code=503, detail="Router not initialized")

        from .detectors import InjectionDetector, JailbreakDetector, PIIDetector, ToxicDetector
        from .detectors import SecretsDetector, FinancialDetector, CloudDetector, CompanyDetector
        from .models import DetectionResult, DetectionFinding

        blocked_result: DetectionResult | None = None

        if bypass_mode != "full":
            combined = _extract_body_text(body)
            scan_results = []
            if bypass_mode not in ("injection",):
                scan_results += [
                    InjectionDetector(threshold=settings.injection_threshold).scan(combined),
                    JailbreakDetector().scan(combined),
                    ToxicDetector().scan(combined),
                ]
            if bypass_mode not in ("pii",):
                scan_results += [
                    PIIDetector().scan(combined, context="input"),
                    SecretsDetector().scan(combined),
                    FinancialDetector().scan(combined),
                    CloudDetector().scan(combined),
                    CompanyDetector().scan(combined),
                ]

            all_findings: list[DetectionFinding] = []
            for r in scan_results:
                all_findings.extend(r.findings)

            if any(r.blocked for r in scan_results):
                blocked_result = DetectionResult(blocked=True, findings=all_findings)

        pii_detector = PIIDetector(mask_output=settings.pii_mask_output)

        return StreamingResponse(
            _streamer.stream(
                provider=provider,
                path=f"/{path}",
                body=body,
                request_id=request_id,
                input_blocked_result=blocked_result,
                pii_detector=pii_detector,
                stats=_stats,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "X-Request-Id": request_id,
            },
        )

    # ── Non-streaming path ────────────────────────────────────────────
    if not _router:
        raise HTTPException(status_code=503, detail="Router not initialized")

    start_time = time.perf_counter()
    response_body, status_code = await _router.handle(
        provider=provider,
        path=f"/{path}",
        headers=dict(request.headers),
        body=body,
    )
    latency_ms = int((time.perf_counter() - start_time) * 1000)

    # Record stats
    if _stats:
        detector_findings = _extract_finding_counts(response_body)
        blocked = status_code == 400 and "prompt_armor_blocked" in str(response_body)
        await _stats.record_request(
            provider=provider,
            blocked=blocked,
            latency_ms=latency_ms,
            detector_findings=detector_findings,
        )
        # Extract token usage from successful response
        usage = _extract_usage(response_body, provider)
        if usage:
            await _stats.record_tokens(provider=provider, **usage)

    return JSONResponse(
        content=response_body,
        status_code=status_code,
        headers={"X-Request-Id": request_id},
    )


def _extract_body_text(body: dict[str, Any]) -> str:
    texts = []
    for msg in body.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))
    if "prompt" in body:
        p = body["prompt"]
        texts.append(p if isinstance(p, str) else " ".join(p))
    return "\n".join(t for t in texts if t.strip())


def _extract_finding_counts(response_body: dict[str, Any]) -> dict[str, int]:
    findings = response_body.get("error", {}).get("findings", [])
    counts: dict[str, int] = {}
    for f in findings:
        cat = f.get("category", "unknown")
        counts[cat] = counts.get(cat, 0) + 1
    return counts


def _extract_usage(response_body: dict[str, Any], provider: str) -> dict[str, int]:
    usage = response_body.get("usage", {})
    if not usage:
        return {}
    return {
        "input_tokens": usage.get("prompt_tokens", usage.get("input_tokens", 0)),
        "output_tokens": usage.get("completion_tokens", usage.get("output_tokens", 0)),
    }


# ── Provider routes ───────────────────────────────────────────────────

@app.post("/openai/{path:path}", tags=["OpenAI"], response_model=None)
async def proxy_openai(request: Request, path: str) -> Any:
    """Drop-in replacement. Change base_url to http://localhost:8000/openai — supports streaming."""
    return await _proxy_request(request, "openai", path)


@app.post("/anthropic/{path:path}", tags=["Anthropic"], response_model=None)
async def proxy_anthropic(request: Request, path: str) -> Any:
    """Drop-in replacement. Change base_url to http://localhost:8000/anthropic — supports streaming."""
    return await _proxy_request(request, "anthropic", path)


@app.post("/bedrock/{path:path}", tags=["AWS Bedrock"], response_model=None)
async def proxy_bedrock(request: Request, path: str) -> Any:
    """AWS Bedrock proxy. Uses boto3 default credential chain."""
    return await _proxy_request(request, "bedrock", path)


@app.post("/azure/{path:path}", tags=["Azure OpenAI"], response_model=None)
async def proxy_azure(request: Request, path: str) -> Any:
    """Azure OpenAI proxy. Set ARMOR_AZURE_OPENAI_ENDPOINT in .env"""
    return await _proxy_request(request, "azure", path)


@app.post("/ollama/{path:path}", tags=["Ollama"], response_model=None)
async def proxy_ollama(request: Request, path: str) -> Any:
    """Ollama proxy. Supports streaming. Set ARMOR_OLLAMA_BASE_URL in .env"""
    return await _proxy_request(request, "ollama", path)


@app.post("/gemini/{path:path}", tags=["Google Gemini"], response_model=None)
async def proxy_gemini(request: Request, path: str) -> Any:
    """Google Gemini proxy. Set ARMOR_GEMINI_API_KEY. Accepts OpenAI-compat format."""
    return await _proxy_request(request, "gemini", path)


@app.post("/groq/{path:path}", tags=["Groq"], response_model=None)
async def proxy_groq(request: Request, path: str) -> Any:
    """Groq proxy. Set ARMOR_GROQ_API_KEY. Drop-in OpenAI-compat. Supports streaming."""
    return await _proxy_request(request, "groq", path)


@app.post("/mistral/{path:path}", tags=["Mistral"], response_model=None)
async def proxy_mistral(request: Request, path: str) -> Any:
    """Mistral AI proxy. Set ARMOR_MISTRAL_API_KEY. Supports streaming."""
    return await _proxy_request(request, "mistral", path)


@app.post("/cohere/{path:path}", tags=["Cohere"], response_model=None)
async def proxy_cohere(request: Request, path: str) -> Any:
    """Cohere proxy. Set ARMOR_COHERE_API_KEY. Accepts OpenAI-compat format."""
    return await _proxy_request(request, "cohere", path)


@app.post("/deepseek/{path:path}", tags=["DeepSeek"], response_model=None)
async def proxy_deepseek(request: Request, path: str) -> Any:
    """DeepSeek proxy. Set ARMOR_DEEPSEEK_API_KEY. Drop-in OpenAI-compat. Supports streaming."""
    return await _proxy_request(request, "deepseek", path)


# ── Scan endpoints ────────────────────────────────────────────────────

@app.post("/scan", tags=["Scan Only"])
async def scan_only(request: Request) -> JSONResponse:
    """
    Scan a single text without forwarding to any LLM.

    Body: { "text": "...", "context": "input|output" }
    """
    _verify_auth(request)
    body = await request.json()
    text = body.get("text", "")
    context = body.get("context", "input")

    if not text:
        raise HTTPException(status_code=400, detail="'text' field required")

    return JSONResponse(_run_all_scans(text, context))


@app.post("/scan/batch", tags=["Scan Only"])
async def scan_batch(request: Request) -> JSONResponse:
    """
    Scan an array of messages (conversation format) without forwarding.

    Body: { "messages": [{"role": "user", "content": "..."}], "context": "input|output" }

    Returns per-message findings + aggregated blocked status.
    Designed for teams scanning full conversation history.
    """
    _verify_auth(request)
    body = await request.json()
    messages = body.get("messages", [])
    context = body.get("context", "input")

    if not messages:
        raise HTTPException(status_code=400, detail="'messages' array required")
    if len(messages) > 100:
        raise HTTPException(status_code=400, detail="Max 100 messages per batch")

    results = []
    any_blocked = False

    for i, msg in enumerate(messages):
        content = msg.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                b.get("text", "") for b in content if isinstance(b, dict)
            )

        if not content.strip():
            results.append({"index": i, "role": msg.get("role"), "blocked": False, "findings": []})
            continue

        scan = _run_all_scans(content, context)
        blocked = scan["blocked"]
        any_blocked = any_blocked or blocked

        results.append({
            "index": i,
            "role": msg.get("role"),
            "blocked": blocked,
            "findings": [
                f
                for detector_result in scan["results"].values()
                for f in detector_result.get("findings", [])
            ],
        })

    return JSONResponse({
        "blocked": any_blocked,
        "message_count": len(messages),
        "blocked_count": sum(1 for r in results if r["blocked"]),
        "messages": results,
    })


@app.post("/scan/explain", tags=["Scan Only"])
async def scan_explain(request: Request) -> JSONResponse:
    """
    Scan text and return a human-readable explanation of every finding.
    Use this to debug why a request was blocked — not just what triggered it.

    Body: { "text": "...", "context": "input|output" }

    Returns: blocked status + plain English explanation per finding.
    """
    _verify_auth(request)
    body = await request.json()
    text = body.get("text", "")
    context = body.get("context", "input")

    if not text:
        raise HTTPException(status_code=400, detail="'text' field required")

    scan = _run_all_scans(text, context)

    explanations = []
    for detector, result in scan["results"].items():
        for finding in result.get("findings", []):
            explanations.append({
                "detector": detector,
                "severity": finding["severity"],
                "blocked": finding["severity"] in ("critical", "high"),
                "explanation": _explain_finding(finding),
                "recommendation": _recommend_finding(finding),
            })

    return JSONResponse({
        "blocked": scan["blocked"],
        "finding_count": len(explanations),
        "explanation": (
            f"This request was blocked because {len(explanations)} security finding(s) were detected."
            if scan["blocked"]
            else "This request passed all security checks."
        ),
        "findings": explanations,
    })


def _explain_finding(finding: dict[str, Any]) -> str:
    """Human-readable explanation for each finding type."""
    category = finding.get("category", "")
    description = finding.get("description", "")

    explanations: dict[str, str] = {
        "prompt_injection": (
            f"Prompt injection detected: '{description}'. "
            "This pattern attempts to override the AI system's instructions. "
            "Attackers use this to make the AI ignore its safety guidelines or reveal system prompts."
        ),
        "jailbreak": (
            f"Jailbreak attempt detected: '{description}'. "
            "This pattern tries to bypass the AI's safety training. "
            "Common techniques include DAN prompts, developer mode requests, and role-play exploits."
        ),
        "pii_input": (
            f"Personally Identifiable Information detected: '{description}'. "
            "Sending PII to external AI providers may violate DPDP Act, GDPR, or internal data policies. "
            "Remove or anonymize this information before sending to the AI."
        ),
        "pii_output": (
            f"PII detected in AI response: '{description}'. "
            "The AI output contained personal information. "
            "This has been masked before returning to your application."
        ),
        "toxic": (
            f"Harmful content request detected: '{description}'. "
            "This request asks for content that could cause real-world harm. "
            "This category is always blocked regardless of configuration."
        ),
    }

    return explanations.get(category, f"{description}. Category: {category}.")


def _recommend_finding(finding: dict[str, Any]) -> str:
    """Actionable recommendation for each finding type."""
    category = finding.get("category", "")
    severity = finding.get("severity", "")

    recs: dict[str, str] = {
        "prompt_injection": "Validate and sanitize all user input before passing to the LLM. Use structural separation between system instructions and user content.",
        "jailbreak": "Review your system prompt hardening. Consider adding explicit anti-jailbreak instructions. Monitor repeated attempts from the same user.",
        "pii_input": "Strip PII before sending to LLM, or configure ARMOR_PII_INPUT_ACTION=warn if this service legitimately needs PII. Add this service to the allowlist if intentional.",
        "pii_output": "Output PII has been masked. Consider whether your system prompt should instruct the model to avoid repeating personal information.",
        "toxic": "This request violated zero-tolerance policies. Consider blocking the user account and investigating the source.",
    }

    return recs.get(category, f"Review the {severity} severity finding and adjust your application or prompt-armor configuration.")


def _demo_stats() -> dict[str, Any]:
    """Seeded demo data for README/demo mode. Shows realistic production stats."""
    return {
        "summary": {
            "total_requests": 48291,
            "total_blocked": 1847,
            "overall_block_rate_pct": 3.8,
        },
        "by_provider": [
            {"provider": "openai", "requests": 28450, "blocked": 1102, "block_rate_pct": 3.9, "avg_latency_ms": 847, "errors": 12, "tokens": {"input": 14200000, "output": 8900000, "total": 23100000}},
            {"provider": "anthropic", "requests": 12891, "blocked": 498, "block_rate_pct": 3.9, "avg_latency_ms": 1240, "errors": 4, "tokens": {"input": 6400000, "output": 3200000, "total": 9600000}},
            {"provider": "groq", "requests": 4820, "blocked": 187, "block_rate_pct": 3.9, "avg_latency_ms": 312, "errors": 2, "tokens": {"input": 2100000, "output": 980000, "total": 3080000}},
            {"provider": "bedrock", "requests": 2130, "blocked": 60, "block_rate_pct": 2.8, "avg_latency_ms": 1890, "errors": 1, "tokens": {"input": 980000, "output": 420000, "total": 1400000}},
        ],
        "findings_by_detector": {
            "prompt_injection": 624,
            "pii_input": 589,
            "secrets": 312,
            "jailbreak": 198,
            "financial": 87,
            "cloud": 24,
            "toxic": 13,
        },
        "note": "DEMO MODE — set ARMOR_DEMO_MODE=false for real stats",
    }


def _run_all_scans(text: str, context: str = "input") -> dict[str, Any]:
    from .detectors import (
        CloudDetector, CompanyDetector, FinancialDetector,
        InjectionDetector, JailbreakDetector, PIIDetector,
        SecretsDetector, ToxicDetector,
    )

    results = {
        "injection":  InjectionDetector().scan(text).model_dump(),
        "jailbreak":  JailbreakDetector().scan(text).model_dump(),
        "pii":        PIIDetector().scan(text, context=context).model_dump(),
        "secrets":    SecretsDetector().scan(text).model_dump(),
        "financial":  FinancialDetector().scan(text).model_dump(),
        "cloud":      CloudDetector().scan(text).model_dump(),
        "company":    CompanyDetector().scan(text).model_dump(),
        "toxic":      ToxicDetector().scan(text).model_dump(),
    }
    any_blocked = any(r["blocked"] for r in results.values())
    return {"blocked": any_blocked, "results": results}


def start() -> None:
    uvicorn.run(
        "prompt_armor.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.value.lower(),
        access_log=False,
    )


if __name__ == "__main__":
    start()
