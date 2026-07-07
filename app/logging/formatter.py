import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from app.logging.context import client_trace_id_var, ip_var, request_id_var

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

_BUILTIN_LOGRECORD_ATTRS: frozenset[str] = frozenset(
    logging.LogRecord(
        name="", level=0, pathname="", lineno=0, msg="", args=(), exc_info=None
    ).__dict__.keys()
) | {"message", "asctime", "event_id", "stream"}


def _sanitize_message(value: str) -> str:
    return _CONTROL_CHARS.sub("", value)


def _collect_context() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, var in (
        ("request_id", request_id_var),
        ("ip", ip_var),
        ("client_trace_id", client_trace_id_var),
    ):
        value = var.get()
        if value != "-":
            out[key] = value
    return out


def _collect_extras(record: logging.LogRecord) -> dict[str, Any]:
    return {
        k: v for k, v in record.__dict__.items() if k not in _BUILTIN_LOGRECORD_ATTRS
    }


class JsonFormatter(logging.Formatter):
    """Structured JSON formatter for the debug-json view.

    Example output:
        {
            "event_id": "100601",
            "timestamp": "2026-04-23T10:11:12Z",
            "level": "INFO",
            "event_description": "Application started",
            "source": "app.application:123",
            "message": {
                "version": "...",
                "environment": "...",
                "request_id": "...",
                ...
            }
        }
    """

    def __init__(self, include_traces: bool = True) -> None:
        super().__init__()
        self.include_traces = include_traces

    def format(self, record: logging.LogRecord) -> str:
        message: dict[str, Any] = {}

        if record.exc_info and self.include_traces:
            message["exception"] = self.formatException(record.exc_info)
        if record.stack_info and self.include_traces:
            message["stack_info"] = self.formatStack(record.stack_info)

        message.update(_collect_context())
        message.update(_collect_extras(record))

        log_record: dict[str, Any] = {
            "event_id": getattr(record, "event_id", None),
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "event_description": _sanitize_message(record.getMessage()),
            "source": f"{record.module}:{record.lineno}",
        }
        log_record["message"] = message

        return json.dumps(log_record, default=str)


class PlainTextFormatter(logging.Formatter):
    """Human-readable formatter for the debug-stdout view.

    Example output:
        2026-04-23T10:11:12Z INFO app.application [100601] Application started version=...
    """

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        event_id = getattr(record, "event_id", None) or "-"
        base = (
            f"{timestamp} {record.levelname:<8} {record.name} "
            f"[{event_id}] {_sanitize_message(record.getMessage())}"
        )

        pairs: list[str] = []
        for key, value in _collect_context().items():
            pairs.append(f"{key}={value}")
        for key, value in _collect_extras(record).items():
            pairs.append(f"{key}={value}")

        out = base if not pairs else f"{base} {' '.join(pairs)}"

        if record.exc_info:
            out = f"{out}\n{self.formatException(record.exc_info)}"
        return out
