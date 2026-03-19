"""Entry-point for the Threat Intelligence Agent.

Starts a health/metrics server on a background thread and then enters
a Kafka consume loop.  Falls back to API-only mode when Kafka is
unavailable.
"""

from __future__ import annotations

import json
import threading
import time

import structlog
import uvicorn

from threat_intelligence_agent.config import get_settings
from threat_intelligence_agent.graph import get_compiled_graph
from threat_intelligence_agent.monitoring.health import health_app

logger = structlog.get_logger(__name__)


def _start_health_server() -> None:
    settings = get_settings()
    uvicorn.run(health_app, host="0.0.0.0", port=settings.health_port, log_level="warning")


def _consume_kafka() -> None:
    """Blocking Kafka consumer loop — processes inbound intel records."""
    settings = get_settings()
    try:
        from confluent_kafka import Consumer, KafkaError  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("confluent_kafka not installed – skipping Kafka consumer")
        return

    conf = {
        "bootstrap.servers": settings.kafka_bootstrap,
        "group.id": settings.kafka_group_id,
        "auto.offset.reset": "latest",
    }

    try:
        consumer = Consumer(conf)
    except Exception as exc:
        logger.warning("kafka.connect_failed", error=str(exc))
        return

    consumer.subscribe([settings.kafka_topic])
    graph = get_compiled_graph()
    logger.info("kafka.consumer_started", topic=settings.kafka_topic)

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error("kafka.error", error=msg.error())
                continue
            try:
                payload = json.loads(msg.value().decode("utf-8"))
                records = payload if isinstance(payload, list) else [payload]
                graph.invoke({"raw_intel": records})
                logger.info("kafka.processed", count=len(records))
            except Exception as exc:
                logger.error("kafka.process_error", error=str(exc))
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()


def _run_api_server() -> None:
    """Start the BFF API for GUI / manual interaction."""
    from threat_intelligence_agent.api.app import app  # noqa: WPS433

    settings = get_settings()
    uvicorn.run(app, host="0.0.0.0", port=settings.api_port, log_level="info")


def main() -> None:
    settings = get_settings()
    logger.info(
        "threat_intelligence_agent.starting",
        env=settings.agent_env,
        api_port=settings.api_port,
        health_port=settings.health_port,
    )

    # Background: health + metrics server
    health_thread = threading.Thread(target=_start_health_server, daemon=True)
    health_thread.start()

    # Try Kafka; fall back to API-only
    try:
        from confluent_kafka import Consumer  # type: ignore[import-untyped]

        kafka_thread = threading.Thread(target=_consume_kafka, daemon=True)
        kafka_thread.start()
        logger.info("kafka.thread_started")
    except ImportError:
        logger.info("kafka.unavailable_falling_back_to_api")

    _run_api_server()


if __name__ == "__main__":
    main()
