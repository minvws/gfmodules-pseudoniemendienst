import logging
from dataclasses import dataclass
from typing import Any

from app.logging.filters import LoggingStreams


@dataclass(frozen=True)
class PRSEvent:
    event_id: str
    level: int
    streams: tuple[LoggingStreams, ...]


OPRF_EVAL_OK = PRSEvent(
    "210400", logging.INFO, (LoggingStreams.APP, LoggingStreams.SIEM)
)
OPRF_EVAL_FAILED = PRSEvent(
    "210402", logging.ERROR, (LoggingStreams.APP, LoggingStreams.SIEM)
)
OPRF_REFUSED_NO_ACTIVE_PUBKEY = PRSEvent(
    "210403", logging.WARNING, (LoggingStreams.APP, LoggingStreams.SIEM)
)

ACCESS_REQUEST = PRSEvent("001000", logging.INFO, (LoggingStreams.APP,))


def log_event(
    logger: logging.Logger,
    event: PRSEvent,
    message: str,
    *,
    exc_info: Any = None,
    **fields: Any,
) -> None:
    extra: dict[str, Any] = {
        "event_id": event.event_id,
        "stream": list(event.streams),
    }
    extra.update(fields)
    logger.log(event.level, message, extra=extra, exc_info=exc_info)
