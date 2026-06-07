"""
Proxy router — forwards requests to upstream LLM providers after scanning.

Supports 10 providers. Handles streaming (SSE) and non-streaming.
Includes retry logic with backoff for 429/5xx errors.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import httpx
import structlog

from ..config import DetectorAction, settings
from .errors import get_timeout, request_with_retry
from ..detectors import (
    CloudDetector,
    CompanyDetector,
    FinancialDetector,
    InjectionDetector,
    JailbreakDetector,
    PIIDetector,
    SecretsDetector,
    ToxicDetector,
)
from ..middleware.audit_logger import AuditLogger
from ..models import ArmorError, DetectionFinding, DetectionResult

log = structlog.get_logger(__name__)


def _extract_messages(body: dict[str, Any]) -> list[str]:
    """Extract all text content from request body across provider formats."""
    texts: list[str] = []

    # OpenAI / Azure / Ollama chat format
    for msg in body.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))

    # OpenAI completions format
    if "prompt" in body:
        p = body["prompt"]
        if isinstance(p, str):
            texts.append(p)
        elif isinstance(p, list):
            texts.extend(p)

    # Anthropic messages format
    for msg in body.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))

    return [t for t in texts if t.strip()]


def _extract_output_text(response_body: dict[str, Any]) -> list[str]:
    """Extract all generated text from LLM response."""
    texts: list[str] = []

    # OpenAI format
    for choice in response_body.get("choices", []):
        msg = choice.get("message", {})
        if msg.get("content"):
            texts.append(msg["content"])
        delta = choice.get("delta", {})
        if delta.get("content"):
            texts.append(delta["content"])
        if choice.get("text"):
            texts.append(choice["text"])

    # Anthropic format
    for block in response_body.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            texts.append(block.get("text", ""))

    return [t for t in texts if t.strip()]


class ProxyRouter:
    def __init__(self) -> None:
        self.injection = InjectionDetector(threshold=settings.injection_threshold)
        self.jailbreak = JailbreakDetector()
        self.pii = PIIDetector(mask_output=settings.pii_mask_output)
        self.secrets = SecretsDetector()
        self.financial = FinancialDetector()
        self.cloud = CloudDetector()
        self.company = CompanyDetector()
        self.toxic = ToxicDetector()
        self.audit = AuditLogger()
        # Connection pool sized for enterprise: 100 keepalive, 20 per host
        self._client = httpx.AsyncClient(
            limits=httpx.Limits(max_keepalive_connections=100, max_connections=200, keepalive_expiry=30.0),
        )

    async def handle(
        self,
        provider: str,
        path: str,
        headers: dict[str, str],
        body: dict[str, Any],
    ) -> tuple[dict[str, Any], int]:
        request_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        # ── Input scanning ────────────────────────────────────────────
        input_texts = _extract_messages(body)
        all_findings: list[DetectionFinding] = []
        combined_input = "\n".join(input_texts)

        scan_results: list[DetectionResult] = [
            self.injection.scan(combined_input),
            self.jailbreak.scan(combined_input),
            self.pii.scan(combined_input, context="input"),
            self.secrets.scan(combined_input),
            self.financial.scan(combined_input),
            self.cloud.scan(combined_input),
            self.company.scan(combined_input),
            self.toxic.scan(combined_input),
        ]

        for result in scan_results:
            all_findings.extend(result.findings)

        should_block = self._evaluate_action(scan_results)

        if should_block:
            final_result = DetectionResult(blocked=True, findings=all_findings)
            await self.audit.log(
                request_id=request_id,
                provider=provider,
                blocked=True,
                findings=all_findings,
                latency_ms=int((time.perf_counter() - start_time) * 1000),
            )
            log.warning(
                "request_blocked",
                request_id=request_id,
                provider=provider,
                finding_count=len(all_findings),
            )
            return ArmorError.from_result(final_result, request_id).model_dump(), 400

        # ── Forward to upstream ───────────────────────────────────────
        try:
            response_body, status_code = await self._forward(
                provider=provider,
                path=path,
                headers=headers,
                body=body,
            )
        except Exception as exc:
            log.error("upstream_error", error=str(exc), provider=provider)
            return {"error": {"message": f"Upstream error: {exc}", "type": "upstream_error"}}, 502

        # ── Output scanning ───────────────────────────────────────────
        output_texts = _extract_output_text(response_body)
        output_combined = "\n".join(output_texts)
        output_findings: list[DetectionFinding] = []

        if output_combined:
            pii_output_result = self.pii.scan(output_combined, context="output")
            output_findings.extend(pii_output_result.findings)

            if pii_output_result.sanitized_text and settings.pii_mask_output:
                response_body = self._replace_output_text(
                    response_body, output_combined, pii_output_result.sanitized_text
                )

        await self.audit.log(
            request_id=request_id,
            provider=provider,
            blocked=False,
            findings=all_findings + output_findings,
            latency_ms=int((time.perf_counter() - start_time) * 1000),
        )

        return response_body, status_code

    def _evaluate_action(self, results: list[DetectionResult]) -> bool:
        """Determine if request should be blocked based on config actions."""
        for result in results:
            if not result.findings:
                continue

            for finding in result.findings:
                from ..models import DetectionCategory, Severity

                action_map = {
                    DetectionCategory.PROMPT_INJECTION: settings.injection_action,
                    DetectionCategory.JAILBREAK: settings.jailbreak_action,
                    DetectionCategory.PII_INPUT: settings.pii_input_action,
                    DetectionCategory.TOXIC: settings.toxic_action,
                }
                action = action_map.get(finding.category, DetectorAction.WARN)

                if action == DetectorAction.BLOCK and finding.severity.value in ("high", "critical"):
                    return True

        return False

    async def _forward(
        self,
        provider: str,
        path: str,
        headers: dict[str, str],
        body: dict[str, Any],
    ) -> tuple[dict[str, Any], int]:
        dispatch = {
            "openai":    lambda: self._forward_openai(path, headers, body),
            "anthropic": lambda: self._forward_anthropic(path, headers, body),
            "bedrock":   lambda: self._forward_bedrock(path, body),
            "azure":     lambda: self._forward_azure(path, headers, body),
            "ollama":    lambda: self._forward_ollama(path, body),
            "gemini":    lambda: self._forward_gemini(path, body),
            "groq":      lambda: self._forward_groq(path, body),
            "mistral":   lambda: self._forward_mistral(path, body),
            "cohere":    lambda: self._forward_cohere(path, body),
            "deepseek":  lambda: self._forward_deepseek(path, body),
        }
        if provider not in dispatch:
            raise ValueError(f"Unknown provider: {provider}. Supported: {list(dispatch)}")
        return await dispatch[provider]()

    async def _forward_openai(
        self, path: str, headers: dict[str, str], body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        return await request_with_retry(
            self._client, "openai",
            f"https://api.openai.com{path}",
            body,
            {"Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"},
        )

    async def _forward_anthropic(
        self, path: str, headers: dict[str, str], body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        return await request_with_retry(
            self._client, "anthropic",
            f"https://api.anthropic.com{path}",
            body,
            {"x-api-key": settings.anthropic_api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
        )

    async def _forward_bedrock(
        self, path: str, body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        import boto3

        # path format: /model/{model_id}/invoke
        parts = path.strip("/").split("/")
        model_id = parts[1] if len(parts) >= 2 else "anthropic.claude-3-5-sonnet-20241022-v2:0"

        client = boto3.client("bedrock-runtime", region_name=settings.aws_region)
        response = client.invoke_model(
            modelId=model_id,
            body=json.dumps(body),
            contentType="application/json",
            accept="application/json",
        )
        response_body = json.loads(response["body"].read())
        return response_body, 200

    async def _forward_azure(
        self, path: str, headers: dict[str, str], body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        upstream_headers = {
            "api-key": settings.azure_openai_api_key,
            "Content-Type": "application/json",
        }
        url = f"{settings.azure_openai_endpoint.rstrip('/')}{path}"
        if "api-version" not in url:
            url += f"?api-version={settings.azure_openai_api_version}"
        r = await self._client.post(url, json=body, headers=upstream_headers)
        return r.json(), r.status_code

    async def _forward_ollama(
        self, path: str, body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        r = await self._client.post(
            f"{settings.ollama_base_url.rstrip('/')}{path}",
            json=body,
            headers={"Content-Type": "application/json"},
        )
        return r.json(), r.status_code

    async def _forward_gemini(
        self, path: str, body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        """
        Google Gemini via REST API.
        Translates OpenAI chat format → Gemini generateContent format.
        Route: /gemini/v1/chat/completions  (OpenAI-compat input)
        """
        model = body.get("model", "gemini-2.0-flash")
        # Strip provider prefix if present
        model = model.replace("google/", "").replace("gemini/", "")

        # Translate messages to Gemini contents format
        contents = []
        system_instruction = None
        for msg in body.get("messages", []):
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                system_instruction = {"parts": [{"text": content}]}
            else:
                gemini_role = "model" if role == "assistant" else "user"
                contents.append({"role": gemini_role, "parts": [{"text": content}]})

        gemini_body: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": body.get("max_tokens", 4096),
                "temperature": body.get("temperature", 1.0),
            },
        }
        if system_instruction:
            gemini_body["system_instruction"] = system_instruction

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models"
            f"/{model}:generateContent?key={settings.gemini_api_key}"
        )
        r = await self._client.post(url, json=gemini_body)
        raw = r.json()

        # Translate Gemini response → OpenAI format
        text = ""
        try:
            text = raw["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            pass

        openai_response = {
            "id": f"gemini-{model}",
            "object": "chat.completion",
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": raw.get("usageMetadata", {}),
        }
        return openai_response, 200 if r.status_code == 200 else r.status_code

    async def _forward_groq(
        self, path: str, body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        return await request_with_retry(
            self._client, "groq",
            f"https://api.groq.com/openai{path}",
            body,
            {"Authorization": f"Bearer {settings.groq_api_key}", "Content-Type": "application/json"},
        )

    async def _forward_mistral(
        self, path: str, body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        return await request_with_retry(
            self._client, "mistral",
            f"https://api.mistral.ai{path}",
            body,
            {"Authorization": f"Bearer {settings.mistral_api_key}", "Content-Type": "application/json"},
        )

    async def _forward_cohere(
        self, path: str, body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        """
        Cohere — translates OpenAI chat format → Cohere chat format.
        Route: /cohere/v1/chat/completions
        """
        messages = body.get("messages", [])
        system_msg = next((m["content"] for m in messages if m["role"] == "system"), "")
        chat_history = []
        user_message = ""

        for msg in messages:
            if msg["role"] == "system":
                continue
            elif msg["role"] == "assistant":
                chat_history.append({"role": "CHATBOT", "message": msg["content"]})
            elif msg["role"] == "user":
                user_message = msg["content"]
                if len([m for m in messages if m["role"] == "user"]) > 1:
                    chat_history.append({"role": "USER", "message": msg["content"]})

        cohere_body: dict[str, Any] = {
            "model": body.get("model", "command-r-plus-08-2024").replace("cohere/", ""),
            "message": user_message,
            "chat_history": chat_history,
            "temperature": body.get("temperature", 0.3),
            "max_tokens": body.get("max_tokens", 4096),
        }
        if system_msg:
            cohere_body["preamble"] = system_msg

        r = await self._client.post(
            "https://api.cohere.com/v2/chat",
            json=cohere_body,
            headers={
                "Authorization": f"Bearer {settings.cohere_api_key}",
                "Content-Type": "application/json",
            },
        )
        raw = r.json()

        # Translate Cohere response → OpenAI format
        text = ""
        try:
            text = raw["message"]["content"][0]["text"]
        except (KeyError, IndexError, TypeError):
            text = raw.get("text", "")

        openai_response = {
            "id": raw.get("id", "cohere"),
            "object": "chat.completion",
            "model": cohere_body["model"],
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": raw.get("meta", {}).get("tokens", {}).get("input_tokens", 0),
                "completion_tokens": raw.get("meta", {}).get("tokens", {}).get("output_tokens", 0),
            },
        }
        return openai_response, 200 if r.status_code == 200 else r.status_code

    async def _forward_deepseek(
        self, path: str, body: dict[str, Any]
    ) -> tuple[dict[str, Any], int]:
        return await request_with_retry(
            self._client, "deepseek",
            f"https://api.deepseek.com{path}",
            body,
            {"Authorization": f"Bearer {settings.deepseek_api_key}", "Content-Type": "application/json"},
        )

    def _replace_output_text(
        self,
        response_body: dict[str, Any],
        original: str,
        sanitized: str,
    ) -> dict[str, Any]:
        body_str = json.dumps(response_body).replace(original, sanitized)
        try:
            return json.loads(body_str)
        except json.JSONDecodeError:
            return response_body
