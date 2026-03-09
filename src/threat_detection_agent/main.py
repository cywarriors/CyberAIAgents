"""Threat Detection Agent – application entry point.

Starts the health-check / metrics HTTP server and begins consuming
telemetry from the configured Kafka topic, running each batch through
the LangGraph detection pipeline.
"""

from __future__ import annotations

import signal
import sys
import threading
from typing import Any

import structlog
import uvicorn

from threat_detection_agent.config import get_settings
from threat_detection_agent.graph import get_compiled_graph
from threat_detection_agent.monitoring.health import app as health_app, set_ready

logger = structlog.get_logger(__name__)


def _start_health_server(port: int) -> threading.Thread:
    """Run the FastAPI health/metrics server in a background thread."""

    def _run() -> None:
        uvicorn.run(health_app, host="0.0.0.0", port=port, log_level="warning")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


def _consume_loop() -> None:
    """Main consumption loop – reads from Kafka and invokes the detection graph."""
    settings = get_settings()
    graph = get_compiled_graph()

    try:
        from confluent_kafka import Consumer, KafkaError

        consumer = Consumer(
            {
                "bootstrap.servers": settings.kafka_bootstrap_servers,
                "group.id": settings.kafka_consumer_group,
                "auto.offset.reset": "latest",
            }
        )
        consumer.subscribe([settings.kafka_telemetry_topic])
    except Exception:
        logger.warning(
            "kafka_unavailable",
            msg="Kafka not reachable – falling back to idle mode. "
            "Use the REST API or tests to feed events.",
        )
        set_ready(True)
        # Block until signal
        signal.pause() if hasattr(signal, "pause") else threading.Event().wait()
        return

    set_ready(True)
    logger.info("consumer_started", topic=settings.kafka_telemetry_topic)

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error("kafka_error", error=str(msg.error()))
                continue

            import json

            try:
                raw_event = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("invalid_message", raw=msg.value()[:200])
                continue

            # Run the detection pipeline for a single-event micro-batch
            result = graph.invoke({"raw_events": [raw_event]})
            alerts = result.get("final_alerts", [])
            if alerts:
                logger.info("alerts_generated", count=len(alerts))
    except KeyboardInterrupt:
        logger.info("shutting_down")
    finally:
        consumer.close()


def main() -> None:
    settings = get_settings()
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            structlog.get_level_from_name(settings.log_level)
        ),
    )
    logger.info("starting", env=settings.agent_env)

    _start_health_server(settings.health_check_port)
    _consume_loop()


if __name__ == "__main__":
    main()
