import logging

from gfmodules.logging import DefaultEventCatalogue, LogEvent, LoggingStreams

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM

_Base = DefaultEventCatalogue


class Log(_Base):
    # OPRF exchange events (PRS-OPRF), see
    # https://github.com/minvws/gfmodules-coordination-private/issues/1035
    OPRF_EVAL_OK = LogEvent(  # PRS-OPRF-001
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
    OPRF_EVAL_FAILED = LogEvent(  # PRS-OPRF-003
        "210402",
        logging.ERROR,
        (_APP, _SIEM),
        {
            _APP: (
                "handelende_oin",
                "namens_oin",
                "doel_oin",
                "error_type",
                "endpoint",
            ),
            _SIEM: ("handelende_oin", "namens_oin", "doel_oin", "error_type"),
        },
    )
    OPRF_REFUSED_NO_ACTIVE_PUBKEY = LogEvent(  # PRS-OPRF-004
        "210403",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("handelende_oin", "namens_oin", "doel_oin", "endpoint"),
            _SIEM: ("handelende_oin", "doel_oin"),
        },
    )

    # Health and system events (PRS-HEALTH / PRS-SYS), see
    # https://github.com/minvws/gfmodules-coordination-private/issues/1041
    # PRS-SYS-005 (270405, crypto engine unreachable) is not defined here: this
    # service talks directly to the HSM API, so an unreachable crypto backend is
    # always PRS-SYS-006.
    HEALTH_UNHEALTHY = LogEvent(  # PRS-HEALTH-001
        "270400",
        logging.ERROR,
        (_APP, _SIEM),
        {
            _APP: ("component", "status", "error_detail"),
            _SIEM: ("component", "status"),
        },
    )
    SYS_APP_STARTED = _Base.SYS_APP_STARTED.with_id("270401").add_fields(  # PRS-SYS-001
        fields={_APP: ("environment", "oauth_enabled", "pseudoniem_api_enabled")},
    )
    SYS_APP_STOPPED = _Base.SYS_APP_STOPPED.with_id("270402")  # PRS-SYS-002
    SYS_APP_CRASHED = _Base.SYS_APP_CRASHED.with_id("270402")  # PRS-SYS-002
    SYS_UNHANDLED_EXCEPTION = _Base.SYS_UNHANDLED_EXCEPTION.with_id(
        "270404"
    )  # PRS-SYS-004
    SYS_MISSING_CORRELATION_ID = (
        _Base.SYS_MISSING_CORRELATION_ID.replace(  # PRS-SYS-007
            event_id="270407",
            streams=(_APP, _SIEM),
            fields={
                _APP: ("endpoint", "method"),
                _SIEM: ("endpoint", "method"),
            },
        )
    )
    SYS_DB_CONNECTION_FAILED = LogEvent(  # PRS-SYS-003
        "270403",
        logging.ERROR,
        (_APP, _SIEM),
        {
            _APP: ("datastore", "error_type", "retry_attempt", "backoff_seconds"),
            _SIEM: ("datastore", "error_type"),
        },
    )
    SYS_HSM_UNREACHABLE = LogEvent(  # PRS-SYS-006
        "270406",
        logging.CRITICAL,
        (_APP, _SIEM),
        {
            _APP: ("error_reason", "retry_attempt"),
            _SIEM: ("error_reason",),
        },
    )
