"""Kafka producer and consumer utilities."""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from aiokafka import AIOKafkaProducer, AIOKafkaConsumer

import structlog

logger = structlog.get_logger(__name__)

_producer: AIOKafkaProducer | None = None


async def get_kafka_producer() -> AIOKafkaProducer:
    """Get or create a Kafka producer."""
    global _producer
    if _producer is None:
        servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        _producer = AIOKafkaProducer(
            bootstrap_servers=servers,
            value_serializer=lambda v: json.dumps(v).encode(),
            key_serializer=lambda k: k.encode() if k else None,
        )
        await _producer.start()
        logger.info("Kafka producer started", servers=servers)
    return _producer


async def publish_event(
    topic: str, event_type: str, data: dict[str, Any], key: str | None = None
) -> None:
    """Publish an event to a Kafka topic."""
    prefix = os.getenv("KAFKA_TOPIC_PREFIX", "reconx")
    producer = await get_kafka_producer()
    message = {"event_type": event_type, "data": data}
    await producer.send(f"{prefix}.{topic}", value=message, key=key)
    logger.debug("Kafka event published", topic=topic, event_type=event_type)


async def create_consumer(
    topic: str, group_id: str, handler: Callable
) -> AIOKafkaConsumer:
    """Create a Kafka consumer for a topic."""
    prefix = os.getenv("KAFKA_TOPIC_PREFIX", "reconx")
    servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    consumer = AIOKafkaConsumer(
        f"{prefix}.{topic}",
        bootstrap_servers=servers,
        group_id=group_id,
        value_deserializer=lambda v: json.loads(v.decode()),
        auto_offset_reset="earliest",
    )
    await consumer.start()
    logger.info("Kafka consumer started", topic=topic, group=group_id)
    return consumer


async def close_producer() -> None:
    """Close the Kafka producer."""
    global _producer
    if _producer:
        await _producer.stop()
        _producer = None
