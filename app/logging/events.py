import logging

from gfmodules.logging import DefaultEventCatalogue, LogEvent, LoggingStreams

_APP = LoggingStreams.APP
_SIEM = LoggingStreams.SIEM

_Base = DefaultEventCatalogue

# PRS-KEY "sleuteltype" for the per-organisation OPRF secret and its derived keys.
SLEUTELTYPE_OPRF_SECRET = "oprf_secret"
# PRS-KEY "sleuteltype" for the per-organisation reversible pseudonym AES/HMAC keys.
SLEUTELTYPE_REVERSIBLE_KEY = "reversible_pseudonym_key"


class Log(_Base):
    # Authentication and authorization events (PRS-AUTH), see
    # https://github.com/minvws/gfmodules-coordination-private/issues/1034
    # Only PRS-AUTH-003 is emitted by this service: token validation and mTLS
    # binding are done upstream by the OIN-verifier, which logs the other events.
    AUTHORIZATION_DENIED = LogEvent(  # PRS-AUTH-003
        "200402",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: (
                "handelende_oin",
                "namens_oin",
                "doel_oin",
                "requested_operation",
            ),
            _SIEM: ("handelende_oin", "namens_oin", "doel_oin", "requested_operation"),
        },
    )

    # Pseudonym creation events (PRS-PSE), see
    # https://github.com/minvws/gfmodules-coordination-private/issues/1036
    # PRS-PSE-002/003 (irreversible pseudonym created, dual-version) belong to the
    # server-side irreversible pseudonym endpoint the technical design foresees
    # next to OPRF; that endpoint does not exist yet. Irreversible pseudonyms are
    # exchanged through OPRF today, which has its own events below. Neither the
    # personal ID nor the pseudonym is ever logged.
    PSEUDONYM_REVERSIBLE_CREATED = LogEvent(  # PRS-PSE-001
        "220400",
        logging.INFO,
        (_APP, _SIEM),
        {
            _APP: (
                "handelende_oin",
                "namens_oin",
                "doel_oin",
                "domein",
                "sleutel_versie",
            ),
            _SIEM: ("handelende_oin", "namens_oin", "doel_oin"),
        },
    )
    PSEUDONYM_CREATE_FAILED = LogEvent(  # PRS-PSE-004
        "220403",
        logging.ERROR,
        (_APP, _SIEM),
        {
            _APP: (
                "handelende_oin",
                "namens_oin",
                "doel_oin",
                "error_type",
            ),
            _SIEM: ("handelende_oin", "namens_oin", "doel_oin", "error_type"),
        },
    )
    PERSONAL_ID_VALIDATION_FAILED = LogEvent(  # PRS-PSE-005
        "220404",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("handelende_oin", "namens_oin", "validation_error"),
            _SIEM: ("handelende_oin", "validation_error"),
        },
    )

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
            ),
            _SIEM: ("handelende_oin", "namens_oin", "doel_oin", "error_type"),
        },
    )
    OPRF_REFUSED_NO_ACTIVE_PUBKEY = LogEvent(  # PRS-OPRF-004
        "210403",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("handelende_oin", "namens_oin", "doel_oin"),
            _SIEM: ("handelende_oin", "doel_oin"),
        },
    )

    # DigiD SAML exchange events (PRS-SAML), see
    # https://github.com/minvws/gfmodules-coordination-private/issues/1037
    # PRS-SAML-003 (230402, decryption failed) and PRS-SAML-004 (230403, invalid
    # assertion) are not defined here yet: the current endpoint is a mock that does
    # not decrypt or validate assertions (coordination issue #1088).
    SAML_EXCHANGE_OK = LogEvent(  # PRS-SAML-001
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
    SAML_EXCHANGE_FAILED = LogEvent(  # PRS-SAML-002
        "230401",
        logging.ERROR,
        (_APP, _SIEM),
        {
            _APP: (
                "handelende_oin",
                "namens_oin",
                "doel_oin",
                "error_type",
            ),
            _SIEM: ("handelende_oin", "namens_oin", "doel_oin", "error_type"),
        },
    )

    # Key management, versioning and rotation events (PRS-KEY), see
    # https://github.com/minvws/gfmodules-coordination-private/issues/1039
    # Key material is never logged; only labels and version numbers. The four-eyes
    # fields of PRS-KEY-002 (initiated_by, approved_by) are not defined: this
    # service has no four-eyes flow yet.
    KEY_GENERATED = LogEvent(  # PRS-KEY-001
        "250400",
        logging.INFO,
        (_APP, _SIEM),
        {
            _APP: (
                "sleuteltype",
                "organisatie_oin",
                "domein",
                "secret_id",
                "sleutel_versie",
            ),
            _SIEM: ("sleuteltype", "organisatie_oin"),
        },
    )
    KEY_ROTATION_STARTED = LogEvent(  # PRS-KEY-002
        "250401",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: (
                "sleuteltype",
                "organisatie_oin",
                "domein",
                "oude_versie",
                "nieuwe_versie",
            ),
            _SIEM: ("sleuteltype", "organisatie_oin", "oude_versie", "nieuwe_versie"),
        },
    )
    KEY_GRACE_STARTED = LogEvent(  # PRS-KEY-003
        "250402",
        logging.INFO,
        (_APP, _SIEM),
        {
            _APP: (
                "sleuteltype",
                "organisatie_oin",
                "oude_versie",
                "grace_start",
                "grace_eind",
            ),
            _SIEM: ("sleuteltype", "organisatie_oin", "oude_versie"),
        },
    )
    KEY_VERSION_DESTROYED = LogEvent(  # PRS-KEY-004
        "250403",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("sleuteltype", "organisatie_oin", "vernietigde_versie"),
            _SIEM: ("sleuteltype", "organisatie_oin", "vernietigde_versie"),
        },
    )
    DECRYPT_PUBKEY_REGISTERED = LogEvent(  # PRS-KEY-005
        "250404",
        logging.INFO,
        (_APP, _SIEM),
        {
            _APP: ("organisatie_oin", "key_algoritme", "key_lengte", "key_versie"),
            _SIEM: ("organisatie_oin", "key_algoritme"),
        },
    )
    DECRYPT_PUBKEY_REJECTED = LogEvent(  # PRS-KEY-006
        "250405",
        logging.WARNING,
        (_APP, _SIEM),
        {
            _APP: ("organisatie_oin", "key_algoritme", "rejection_reason"),
            _SIEM: ("organisatie_oin", "key_algoritme", "rejection_reason"),
        },
    )
    HSM_OPERATION_FAILED = LogEvent(  # PRS-KEY-007
        "250406",
        logging.ERROR,
        (_APP, _SIEM),
        {
            _APP: ("operation_type", "error_reason", "retry_attempt"),
            _SIEM: ("operation_type", "error_reason"),
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
        fields={_APP: ("oauth_enabled", "pseudoniem_api_enabled")},
    )
    SYS_APP_STOPPED = _Base.SYS_APP_STOPPED.with_id("270402")  # PRS-SYS-002
    SYS_APP_CRASHED = _Base.SYS_APP_CRASHED.with_id("270402")  # PRS-SYS-002
    SYS_UNHANDLED_EXCEPTION = _Base.SYS_UNHANDLED_EXCEPTION.with_id(
        "270404"
    )  # PRS-SYS-004
    SYS_MISSING_CORRELATION_ID = _Base.SYS_MISSING_CORRELATION_ID.with_id(
        "270407"
    )  # PRS-SYS-007
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
