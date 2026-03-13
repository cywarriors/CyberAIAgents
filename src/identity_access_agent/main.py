"""Entry point – starts health server and Kafka consumer loop."""

from __future__ import annotations

import signal
import threading

import structlog
import uvicorn

from identity_access_agent.config import get_settings
from identity_access_agent.monitoring.health import app as health_app, set_ready

logger = structlog.get_logger(__name__)


def _start_health_server(port: int) -> threading.Thread:
    """Run FastAPI health/metrics server in background thread."""

    def _run() -> None:
        uvicorn.run(health_app, host="0.0.0.0", port=port, log_level="warning")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


def _consume_loop() -> None:
    """Main Kafka consumer – reads auth events, invokes identity risk graph."""
    settings = get_settings()
    from identity_access_agent.graph import get_compiled_graph

    graph = get_compiled_graph()

    try:
        from confluent_kafka import Consumer, KafkaError

        consumer = Consumer(
            {
                "bootstrap.servers": settings.kafka_bootstrap_servers,
                "group.id": settings.kafka_group_id,
                "auto.offset.reset": "latest",
            }
        )
        consumer.subscribe([settings.kafka_topic_auth_events])
    except Exception:
        logger.warning("kafka_unavailable", info="falling back to API-only mode")
        set_ready(True)
        if hasattr(signal, "pause"):
            signal.pause()
        else:
            threading.Event().wait()
        return

    set_ready(True)
    logger.info("consumer_started", topic=settings.kafka_topic_auth_events)

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
                logger.warning("invalid_message")
                continue

            result = graph.invoke({"raw_auth_events": [raw_event]})
            risk_scores = result.get("risk_scores", [])
            if risk_scores:
                logger.info("risk_scores_computed", count=len(risk_scores))
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
    logger.info("starting_identity_access_agent", env=settings.agent_env)
    _start_health_server(settings.health_check_port)
    _consume_loop()


if __name__ == "__main__":
    main()
