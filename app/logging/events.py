import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.logging.filters import LoggingStreams

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM


@dataclass(frozen=True)
class PRSEvent:
    event_id: str
    level: int
    streams: tuple[LoggingStreams, ...]
    # Per-stream allow-list of field names. APP == "stroom 2", SIEM == "stroom 3".
    # When empty, no per-field routing is applied and every field is sent to all
    # streams in ``streams``.
    fields: Mapping[LoggingStreams, tuple[str, ...]] = field(default_factory=dict)


# Authentication and authorization events (PRS-AUTH), see
# https://github.com/minvws/gfmodules-coordination-private/issues/1034
# Only PRS-AUTH-003 is emitted by this service: token validation and mTLS
# binding are done upstream by the OIN-verifier, which logs the other events.
AUTHORIZATION_DENIED = PRSEvent(  # PRS-AUTH-003
    "200402",
    logging.WARNING,
    (_APP, _SIEM),
    {
        _APP: (
            "handelende_oin",
            "namens_oin",
            "doel_oin",
            "requested_operation",
            "endpoint",
            "method",
        ),
        _SIEM: ("handelende_oin", "namens_oin", "doel_oin", "requested_operation"),
    },
)

# Pseudonym creation events (PRS-PSE), see
# https://github.com/minvws/gfmodules-coordination-private/issues/1036
# PRS-PSE-002/003 (irreversible pseudonym created, dual-version) are not defined
# here: irreversible pseudonyms are exchanged through the OPRF, which has its own
# events above. Neither the personal ID nor the pseudonym is ever logged.
PSEUDONYM_REVERSIBLE_CREATED = PRSEvent(  # PRS-PSE-001
    "220400",
    logging.INFO,
    (_APP, _SIEM),
    {
        _APP: ("handelende_oin", "namens_oin", "doel_oin", "domein", "sleutel_versie"),
        _SIEM: ("handelende_oin", "namens_oin", "doel_oin"),
    },
)
PSEUDONYM_CREATE_FAILED = PRSEvent(  # PRS-PSE-004
    "220403",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("handelende_oin", "namens_oin", "doel_oin", "error_type", "endpoint"),
        _SIEM: ("handelende_oin", "namens_oin", "doel_oin", "error_type"),
    },
)
PERSONAL_ID_VALIDATION_FAILED = PRSEvent(  # PRS-PSE-005
    "220404",
    logging.WARNING,
    (_APP, _SIEM),
    {
        _APP: ("handelende_oin", "namens_oin", "validation_error", "endpoint"),
        _SIEM: ("handelende_oin", "validation_error"),
    },
)

# OPRF exchange events (PRS-OPRF), see
# https://github.com/minvws/gfmodules-coordination-private/issues/1035
OPRF_EVAL_OK = PRSEvent(  # PRS-OPRF-001
    "210400",
    logging.INFO,
    (_APP, _SIEM),
    {
        _APP: (
            "handelende_oin",
            "namens_oin",
            "doel_oin",
            "oprf_secret_versie",
            "ontvanger_pubkey_id",
        ),
        _SIEM: ("handelende_oin", "namens_oin", "doel_oin"),
    },
)
OPRF_EVAL_FAILED = PRSEvent(  # PRS-OPRF-003
    "210402",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("handelende_oin", "namens_oin", "doel_oin", "error_type", "endpoint"),
        _SIEM: ("handelende_oin", "namens_oin", "doel_oin", "error_type"),
    },
)
OPRF_REFUSED_NO_ACTIVE_PUBKEY = PRSEvent(  # PRS-OPRF-004
    "210403",
    logging.WARNING,
    (_APP, _SIEM),
    {
        _APP: ("handelende_oin", "namens_oin", "doel_oin", "endpoint"),
        _SIEM: ("handelende_oin", "doel_oin"),
    },
)

# DigiD SAML exchange events (PRS-SAML), see
# https://github.com/minvws/gfmodules-coordination-private/issues/1037
# PRS-SAML-003 (230402, decryption failed) and PRS-SAML-004 (230403, invalid
# assertion) are not defined here yet: the current endpoint is a mock that does
# not decrypt or validate assertions (coordination issue #1088).
SAML_EXCHANGE_OK = PRSEvent(  # PRS-SAML-001
    "230400",
    logging.INFO,
    (_APP, _SIEM),
    {
        _APP: (
            "handelende_oin",
            "namens_oin",
            "doel_oin",
            "domein",
            "saml_decrypt_key_versie",
            "sleutel_versie",
        ),
        _SIEM: ("handelende_oin", "namens_oin", "doel_oin"),
    },
)
SAML_EXCHANGE_FAILED = PRSEvent(  # PRS-SAML-002
    "230401",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("handelende_oin", "namens_oin", "doel_oin", "error_type", "endpoint"),
        _SIEM: ("handelende_oin", "namens_oin", "doel_oin", "error_type"),
    },
)

# Health and system events (PRS-HEALTH / PRS-SYS), see
# https://github.com/minvws/gfmodules-coordination-private/issues/1041
# PRS-SYS-005 (270405, crypto engine unreachable) is not defined here: this
# service talks directly to the HSM API, so an unreachable crypto backend is
# always PRS-SYS-006.
HEALTH_UNHEALTHY = PRSEvent(  # PRS-HEALTH-001
    "270400",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("component", "status", "error_detail"),
        _SIEM: ("component", "status"),
    },
)
SYS_APP_STARTED = PRSEvent(  # PRS-SYS-001 (APP stream only per spec)
    "270401",
    logging.INFO,
    (_APP,),
    {
        _APP: (
            "component",
            "version",
            "environment",
            "oauth_enabled",
            "pseudoniem_api_enabled",
        ),
    },
)
SYS_APP_STOPPED = PRSEvent(  # PRS-SYS-002 (controlled shutdown)
    "270402",
    logging.INFO,
    (_APP, _SIEM),
    {
        _APP: ("component", "shutdown_reason", "last_exception_type"),
        _SIEM: ("component", "shutdown_reason"),
    },
)
SYS_APP_CRASHED = PRSEvent(  # PRS-SYS-002 (uncontrolled shutdown)
    "270402",
    logging.CRITICAL,
    (_APP, _SIEM),
    {
        _APP: ("component", "shutdown_reason", "last_exception_type"),
        _SIEM: ("component", "shutdown_reason"),
    },
)
SYS_DB_CONNECTION_FAILED = PRSEvent(  # PRS-SYS-003
    "270403",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("datastore", "error_type", "retry_attempt", "backoff_seconds"),
        _SIEM: ("datastore", "error_type"),
    },
)
SYS_UNHANDLED_EXCEPTION = PRSEvent(  # PRS-SYS-004
    "270404",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("exception_type", "endpoint", "method"),
        _SIEM: ("exception_type", "endpoint", "method"),
    },
)
SYS_MISSING_CORRELATION_ID = PRSEvent(  # PRS-SYS-007
    "270407",
    logging.ERROR,
    (_APP, _SIEM),
    {
        _APP: ("endpoint", "method"),
        _SIEM: ("endpoint", "method"),
    },
)
SYS_HSM_UNREACHABLE = PRSEvent(  # PRS-SYS-006
    "270406",
    logging.CRITICAL,
    (_APP, _SIEM),
    {
        _APP: ("error_reason", "retry_attempt"),
        _SIEM: ("error_reason",),
    },
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
    if event.fields:
        extra["field_streams"] = event.fields
    extra.update(fields)
    logger.log(event.level, message, extra=extra, exc_info=exc_info)
