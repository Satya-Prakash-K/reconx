"""PostgreSQL async engine and session management using SQLAlchemy 2.0."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

import structlog

logger = structlog.get_logger(__name__)

# Global engine instance
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all ORM models."""
    pass


def get_database_url() -> str:
    """Build the async database URL from environment variables."""
    return os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://reconx:reconx_secure_password@localhost:5432/reconx"
    )


def get_db_engine(database_url: str | None = None) -> AsyncEngine:
    """Get or create the async database engine.

    Args:
        database_url: Optional database URL override.

    Returns:
        AsyncEngine instance.
    """
    global _engine

    if _engine is None:
        url = database_url or get_database_url()
        _engine = create_async_engine(
            url,
            echo=os.getenv("RECONX_DEBUG", "false").lower() == "true",
            pool_size=20,
            max_overflow=10,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        logger.info("PostgreSQL engine created", url=url.split("@")[-1])

    return _engine


def get_session_factory(engine: AsyncEngine | None = None) -> async_sessionmaker[AsyncSession]:
    """Get or create the session factory.

    Args:
        engine: Optional engine override.

    Returns:
        Async session factory.
    """
    global _session_factory

    if _session_factory is None:
        eng = engine or get_db_engine()
        _session_factory = async_sessionmaker(
            eng,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    return _session_factory


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a transactional database session.

    Yields:
        AsyncSession with automatic commit/rollback.

    Usage:
        async with get_db_session() as session:
            result = await session.execute(query)
    """
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def init_db() -> None:
    """Initialize database — create all tables."""
    engine = get_db_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables initialized")


async def close_db() -> None:
    """Close database connections."""
    global _engine, _session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Database connections closed")
