"""Multi-Model LLM Gateway — unified interface for GPT-class, local, and reasoning models.

Supports:
- OpenAI GPT-4o/GPT-4 (cloud reasoning + report generation)
- Ollama local models (privacy-first, fast inference)
- vLLM (GPU-accelerated local inference)
- Embeddings via sentence-transformers
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


class MultiModelGateway:
    """Routes requests to the best available model based on task type."""

    def __init__(self):
        self.providers: dict[str, "LLMProvider"] = {}
        self._init_providers()

    def _init_providers(self):
        # Ollama (always try first — local, fast)
        ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.providers["ollama"] = OllamaProvider(ollama_url)

        # OpenAI (if API key present)
        openai_key = os.getenv("OPENAI_API_KEY", "")
        if openai_key and openai_key != "sk-your-openai-key-here":
            self.providers["openai"] = OpenAIProvider(openai_key)

        # vLLM (GPU inference)
        vllm_url = os.getenv("VLLM_BASE_URL", "")
        if vllm_url:
            self.providers["vllm"] = VLLMProvider(vllm_url)

        logger.info("LLM gateway initialized", providers=list(self.providers.keys()))

    async def generate(
        self,
        prompt: str,
        task_type: str = "general",
        max_tokens: int = 1024,
        temperature: float = 0.3,
    ) -> str:
        """Generate text using the best available model for the task."""
        # Route to best provider based on task type
        provider_order = self._route(task_type)

        for provider_name in provider_order:
            provider = self.providers.get(provider_name)
            if not provider:
                continue
            try:
                return await provider.generate(prompt, max_tokens, temperature)
            except Exception as e:
                logger.debug("Provider failed", provider=provider_name, error=str(e))
                continue

        return "[AI analysis unavailable — no LLM providers configured]"

    def _route(self, task_type: str) -> list[str]:
        """Determine provider priority based on task type."""
        if task_type in ("report", "executive", "explanation"):
            # Prefer GPT-4 for high-quality writing
            return ["openai", "vllm", "ollama"]
        elif task_type in ("code", "poc", "fix"):
            # Prefer local coding models
            return ["vllm", "ollama", "openai"]
        elif task_type in ("reasoning", "analysis", "root_cause"):
            # Prefer reasoning models
            return ["openai", "vllm", "ollama"]
        else:
            return ["ollama", "vllm", "openai"]


class LLMProvider:
    """Base LLM provider interface."""
    async def generate(self, prompt: str, max_tokens: int, temperature: float) -> str:
        raise NotImplementedError


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.model = os.getenv("LLM_MODEL", "llama3.1:8b")

    async def generate(self, prompt: str, max_tokens: int = 1024, temperature: float = 0.3) -> str:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(f"{self.base_url}/api/generate", json={
                "model": self.model, "prompt": prompt, "stream": False,
                "options": {"num_predict": max_tokens, "temperature": temperature},
            })
            resp.raise_for_status()
            return resp.json().get("response", "")


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o")

    async def generate(self, prompt: str, max_tokens: int = 1024, temperature: float = 0.3) -> str:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post("https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [{"role": "system", "content": "You are an expert cybersecurity analyst."},
                                 {"role": "user", "content": prompt}],
                    "max_tokens": max_tokens, "temperature": temperature,
                })
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


class VLLMProvider(LLMProvider):
    """vLLM GPU-accelerated inference."""
    def __init__(self, base_url: str):
        self.base_url = base_url

    async def generate(self, prompt: str, max_tokens: int = 1024, temperature: float = 0.3) -> str:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(f"{self.base_url}/v1/completions", json={
                "prompt": prompt, "max_tokens": max_tokens, "temperature": temperature,
            })
            resp.raise_for_status()
            return resp.json()["choices"][0]["text"]
