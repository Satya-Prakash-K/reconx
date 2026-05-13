"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Settings:
    """Application settings."""
    ENV: str = os.getenv("RECONX_ENV", "development")
    DEBUG: bool = os.getenv("RECONX_DEBUG", "true").lower() == "true"
    SECRET_KEY: str = os.getenv("RECONX_SECRET_KEY", "change-me")

    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    API_WORKERS: int = int(os.getenv("API_WORKERS", "4"))
    CORS_ORIGINS: str = os.getenv("API_CORS_ORIGINS", "http://localhost:3000")

    RATE_LIMIT_GLOBAL: int = int(os.getenv("RATE_LIMIT_GLOBAL_RPM", "1000"))
    RATE_LIMIT_PER_TARGET: int = int(os.getenv("RATE_LIMIT_PER_TARGET_RPM", "100"))

    KAFKA_BOOTSTRAP: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    KAFKA_TOPIC_PREFIX: str = os.getenv("KAFKA_TOPIC_PREFIX", "reconx")

    RECON_ENGINE_HOST: str = os.getenv("RECON_ENGINE_HOST", "localhost")
    RECON_ENGINE_PORT: int = int(os.getenv("RECON_ENGINE_PORT", "50052"))


settings = Settings()
