"""ReconX AI Engine — LLM Gateway with multi-provider support."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


class LLMProvider(ABC):
    """Abstract LLM provider interface."""

    @abstractmethod
    async def generate(self, prompt: str, **kwargs: Any) -> str:
        """Generate text from a prompt."""
        ...

    @abstractmethod
    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for texts."""
        ...


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""

    def __init__(self, base_url: str | None = None, model: str | None = None):
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = model or os.getenv("LLM_MODEL", "llama3.1:8b")
        self.client = httpx.AsyncClient(timeout=120.0)

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        resp = await self.client.post(
            f"{self.base_url}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False, **kwargs},
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    async def embed(self, texts: list[str]) -> list[list[float]]:
        results = []
        for text in texts:
            resp = await self.client.post(
                f"{self.base_url}/api/embeddings",
                json={"model": self.model, "prompt": text},
            )
            resp.raise_for_status()
            results.append(resp.json().get("embedding", []))
        return results


class OpenAIProvider(LLMProvider):
    """OpenAI-compatible API provider (works with OpenAI, vLLM, etc.)."""

    def __init__(self, base_url: str | None = None, api_key: str | None = None, model: str | None = None):
        self.base_url = base_url or os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o")
        self.client = httpx.AsyncClient(
            timeout=120.0,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        resp = await self.client.post(
            f"{self.base_url}/chat/completions",
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": kwargs.get("temperature", 0.3),
                "max_tokens": kwargs.get("max_tokens", 4096),
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    async def embed(self, texts: list[str]) -> list[list[float]]:
        resp = await self.client.post(
            f"{self.base_url}/embeddings",
            json={"model": "text-embedding-3-small", "input": texts},
        )
        resp.raise_for_status()
        return [item["embedding"] for item in resp.json()["data"]]


class LLMGateway:
    """Unified LLM gateway with provider abstraction."""

    def __init__(self):
        provider_name = os.getenv("LLM_PROVIDER", "ollama")
        if provider_name == "openai":
            self.provider = OpenAIProvider()
        elif provider_name == "vllm":
            self.provider = OpenAIProvider(
                base_url=os.getenv("VLLM_BASE_URL", "http://localhost:8001/v1")
            )
        else:
            self.provider = OllamaProvider()

        logger.info("LLM Gateway initialized", provider=provider_name)

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        """Generate text using the configured provider."""
        return await self.provider.generate(prompt, **kwargs)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings using the configured provider."""
        return await self.provider.embed(texts)


# Singleton instance
_gateway: LLMGateway | None = None


def get_llm_gateway() -> LLMGateway:
    global _gateway
    if _gateway is None:
        _gateway = LLMGateway()
    return _gateway
