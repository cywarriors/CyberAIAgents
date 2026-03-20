"""VAPT Agent – application entry point.

Starts the health-check / metrics HTTP server and begins consuming
scan requests from the configured Kafka topic, running each engagement
through the LangGraph VAPT pipeline.
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import threading

import structlog
import uvicorn

from vapt_agent.config import get_settings
from vapt_agent.graph import get_compiled_graph
from vapt_agent.monitoring.health import mark_ready, start_health_server
from vapt_agent.monitoring.metrics import (
    ACTIVE_ENGAGEMENTS,
    ENGAGEMENT_DURATION,
    ENGAGEMENTS_TOTAL,
)

logger = structlog.get_logger(__name__)


def _consume_loop() -> None:
    """Main consumption loop – reads scan requests and runs the VAPT pipeline."""
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
        consumer.subscribe([settings.kafka_scan_requests_topic])
    except Exception:
        logger.warning(
            "kafka_unavailable",
            msg="Kafka not reachable – falling back to idle mode. "
            "Use tests or the REST API to run engagements.",
        )
        mark_ready()
        # Block until signal
        if hasattr(signal, "pause"):
            signal.pause()
        else:
            threading.Event().wait()
        return

    mark_ready()
    logger.info("consumer_started", topic=settings.kafka_scan_requests_topic)

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error("kafka_error", error=str(msg.error()))
                continue

            try:
                payload = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                logger.warning("invalid_message", raw=msg.value()[:200])
                continue

            ACTIVE_ENGAGEMENTS.inc()
            ENGAGEMENTS_TOTAL.inc()
            with ENGAGEMENT_DURATION.time():
                result = graph.invoke({
                    "roe_authorization": payload.get("roe_authorization", {}),
                    "engagement_id": payload.get("engagement_id"),
                })
            ACTIVE_ENGAGEMENTS.dec()

            findings = result.get("published_findings", [])
            logger.info(
                "engagement_complete",
                engagement_id=payload.get("engagement_id"),
                findings=len(findings),
            )
    except KeyboardInterrupt:
        logger.info("shutting_down")
    finally:
        consumer.close()


def main() -> None:
    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
    )
    logger.info("starting", env=settings.agent_env)

    # Start health server in background
    start_health_server()
    
    # Start BFF API server in background thread
    def _run_api():
        from vapt_agent.api.app import app
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8086,
            log_level="info",
        )
    
    api_thread = threading.Thread(target=_run_api, daemon=True, name="vapt-api")
    api_thread.start()
    logger.info("api_server_started", port=8086)
    
    # Run Kafka consumer loop (blocks until interrupted)
    _consume_loop()


if __name__ == "__main__":
    main()
