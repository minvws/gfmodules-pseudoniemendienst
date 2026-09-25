"""Asserts the PRS-KEY events (issue 1039) are emitted correctly."""

import base64
import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests
from conftest import create_signed_jws, generate_rsa_keypair
from gfmodules.logging import LogEvent, LoggingStreams
from starlette.testclient import TestClient

from app.config import ConfigOprf
from app.db.db import Database
from app.db.models import HsmKeyVersionEntity, OrganizationEntity
from app.logging.events import Log
from app.models.oin import Oin, RecipientOrganizationOin
from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.oprf.evaluators import HsmOprfEvaluator, OprfHsmKeyLabel

RecordLogs = Callable[[str], list[logging.LogRecord]]

TEST_OIN = Oin("00000099000000001000")
EVALUATOR_LOGGER = "app.services.oprf.evaluators"
# HTTP-level and key generation failures are logged by the shared HSM client.
HSM_CLIENT_LOGGER = "app.services.hsm.client"


def _events(records: list[logging.LogRecord], event_id: str) -> list[logging.LogRecord]:
    return [r for r in records if getattr(r, "event_id", None) == event_id]


def _hsm_response(payload: object, status_code: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError("boom")
    return response


def _hsm_no_such_key() -> MagicMock:
    """What the HSM API answers when the label has no key: a 422 HSMError."""
    return _hsm_response({"error_description": f"OPRF key '{TEST_OIN}' not found"}, 422)


def _evaluator() -> HsmOprfEvaluator:
    version_service = MagicMock()
    version_service.get_active_version_numbers_by_organization_oin.return_value = [1]
    return HsmOprfEvaluator(
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=version_service,
    )


@pytest.mark.parametrize(
    "event,expected_id,expected_level",
    [
        (Log.KEY_GENERATED, "250400", logging.INFO),
        (Log.KEY_ROTATION_STARTED, "250401", logging.WARNING),
        (Log.KEY_GRACE_STARTED, "250402", logging.INFO),
        (Log.KEY_VERSION_DESTROYED, "250403", logging.WARNING),
        (Log.DECRYPT_PUBKEY_REGISTERED, "250404", logging.INFO),
        (Log.DECRYPT_PUBKEY_REJECTED, "250405", logging.WARNING),
        (Log.HSM_OPERATION_FAILED, "250406", logging.ERROR),
    ],
)
def test_key_events_match_logging_spec(
    event: LogEvent, expected_id: str, expected_level: int
) -> None:
    assert event.event_id == expected_id
    assert event.level == expected_level
    assert event.streams == (LoggingStreams.APP, LoggingStreams.SIEM)
    # "Stroom 3" is always a subset of "stroom 2".
    assert set(event.fields[LoggingStreams.SIEM]) <= set(
        event.fields[LoggingStreams.APP]
    )


def test_lazy_oprf_key_generation_emits_key_generated(
    record_logs: RecordLogs, caplog: pytest.LogCaptureFixture
) -> None:
    # Without the app's logging config the module logger inherits WARNING from
    # the root logger, which would drop this INFO event.
    records = record_logs(EVALUATOR_LOGGER)

    with (
        caplog.at_level(logging.INFO, logger=EVALUATOR_LOGGER),
        patch(
            "app.services.hsm.client.requests.post",
            side_effect=[
                _hsm_no_such_key(),  # oprf_evaluate: key does not exist yet
                _hsm_response({"result": "ok"}),  # keygen
                _hsm_response({"result": "AAAA"}),  # oprf_evaluate, retried
            ],
        ),
    ):
        _evaluator().evaluate(TEST_OIN, b"blinded")

    events = _events(records, "250400")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.sleuteltype == "oprf_secret"  # type: ignore[attr-defined]
    assert record.organisatie_oin == TEST_OIN.value  # type: ignore[attr-defined]
    assert record.secret_id == str(OprfHsmKeyLabel(TEST_OIN, 1))  # type: ignore[attr-defined]
    assert record.sleutel_versie == 1  # type: ignore[attr-defined]
    assert not _events(records, "250406")


def test_existing_oprf_key_does_not_emit_key_generated(
    record_logs: RecordLogs, caplog: pytest.LogCaptureFixture
) -> None:
    records = record_logs(EVALUATOR_LOGGER)

    with (
        caplog.at_level(logging.INFO, logger=EVALUATOR_LOGGER),
        patch(
            "app.services.hsm.client.requests.post",
            side_effect=[_hsm_response({"result": "AAAA"})],
        ),
    ):
        _evaluator().evaluate(TEST_OIN, b"blinded")

    assert not _events(records, "250400")


def test_oprf_key_created_by_another_instance_emits_nothing(
    record_logs: RecordLogs, caplog: pytest.LogCaptureFixture
) -> None:
    """Two instances race on first use: the loser's keygen gets "already
    exists", which is neither a key generation nor a failure."""
    records = record_logs(EVALUATOR_LOGGER)
    client_records = record_logs(HSM_CLIENT_LOGGER)

    with (
        caplog.at_level(logging.INFO, logger=EVALUATOR_LOGGER),
        patch(
            "app.services.hsm.client.requests.post",
            side_effect=[
                _hsm_no_such_key(),
                _hsm_response({"error_description": "Object already exists"}, 422),
                _hsm_response({"result": "AAAA"}),
            ],
        ),
    ):
        result = _evaluator().evaluate(TEST_OIN, b"blinded")

    assert result == {1: base64.b64decode("AAAA")}
    assert not _events(records, "250400")
    assert not _events(client_records, "250406")


def test_hsm_http_error_emits_operation_failed(record_logs: RecordLogs) -> None:
    records = record_logs(HSM_CLIENT_LOGGER)

    with (
        patch(
            "app.services.hsm.client.requests.post",
            return_value=_hsm_response(None, status_code=500),
        ),
        pytest.raises(requests.HTTPError),
    ):
        _evaluator().evaluate(TEST_OIN, b"blinded")

    events = _events(records, "250406")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.ERROR
    assert record.operation_type == "oprf_evaluate"  # type: ignore[attr-defined]
    assert record.error_reason == "http_500"  # type: ignore[attr-defined]
    assert record.exc_info is not None
    # PRS-SYS-006 is for an unreachable HSM only.
    assert not _events(records, "270406")


def test_hsm_keygen_without_result_emits_operation_failed(
    record_logs: RecordLogs,
) -> None:
    records = record_logs(HSM_CLIENT_LOGGER)
    evaluator_records = record_logs(EVALUATOR_LOGGER)

    with (
        patch(
            "app.services.hsm.client.requests.post",
            side_effect=[
                _hsm_no_such_key(),
                _hsm_response({"error": "denied"}),
            ],
        ),
        pytest.raises(ValueError),
    ):
        _evaluator().evaluate(TEST_OIN, b"blinded")

    events = _events(records, "250406")
    assert len(events) == 1
    assert events[0].operation_type == "keygen"  # type: ignore[attr-defined]
    assert events[0].error_reason == "no_result_in_response"  # type: ignore[attr-defined]
    assert not _events(evaluator_records, "250400")


def test_create_key_version_emits_rotation_started(
    record_logs: RecordLogs,
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    records = record_logs("app.services.hsm_key_version_service")

    response = client.post("/administration/key-versions", headers=valid_headers)

    assert response.status_code == 201
    events = _events(records, "250401")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.WARNING
    assert record.sleuteltype == "oprf_secret"  # type: ignore[attr-defined]
    assert (
        record.organisatie_oin  # type: ignore[attr-defined]
        == persisted_organization.external_id.value
    )
    assert record.oude_versie == 1  # type: ignore[attr-defined]
    assert record.nieuwe_versie == 2  # type: ignore[attr-defined]


def test_update_key_version_with_until_dt_emits_grace_started(
    record_logs: RecordLogs,
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    records = record_logs("app.services.hsm_key_version_service")
    created = client.post("/administration/key-versions", headers=valid_headers).json()
    until_dt = datetime.now(timezone.utc) + timedelta(days=30)

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": until_dt.isoformat()},
        headers=valid_headers,
    )

    assert response.status_code == 200
    events = _events(records, "250402")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.sleuteltype == "oprf_secret"  # type: ignore[attr-defined]
    assert (
        record.organisatie_oin  # type: ignore[attr-defined]
        == persisted_organization.external_id.value
    )
    assert record.oude_versie == created["version"]  # type: ignore[attr-defined]
    assert record.grace_eind == until_dt.isoformat()  # type: ignore[attr-defined]
    grace_start = datetime.fromisoformat(record.grace_start)  # type: ignore[attr-defined]
    assert grace_start <= datetime.now(timezone.utc)


def test_update_key_version_clearing_until_dt_emits_nothing(
    record_logs: RecordLogs,
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    records = record_logs("app.services.hsm_key_version_service")
    created = client.post("/administration/key-versions", headers=valid_headers).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": None},
        headers=valid_headers,
    )

    assert response.status_code == 200
    assert not _events(records, "250402")


def _add_expired_version(
    database: Database, organization: OrganizationEntity, version: int
) -> None:
    now = datetime.now(timezone.utc)
    with database.get_db_session() as session:
        session.add(
            HsmKeyVersionEntity(
                organization_id=organization.id,
                version=version,
                from_dt=now - timedelta(days=10),
                until_dt=now - timedelta(days=1),
            )
        )
        session.commit()


def _cleanup_service(database: Database) -> HsmKeyCleanupService:
    return HsmKeyCleanupService(
        ConfigOprf(
            hsm_url="https://hsm.local", hsm_module="softhsm", hsm_slot="SoftHSMLabel"
        ),
        HsmKeyVersionService(database),
    )


def test_cleanup_emits_key_version_destroyed(
    record_logs: RecordLogs,
    database: Database,
    persisted_organization: OrganizationEntity,
) -> None:
    records = record_logs("app.services.hsm_key_cleanup_service")
    _add_expired_version(database, persisted_organization, version=7)

    with patch(
        "app.services.hsm.client.requests.post",
        return_value=_hsm_response({"objects": [{"label": "x"}]}),
    ):
        cleaned = _cleanup_service(database).cleanup_expired_keys()

    assert cleaned == 1
    events = _events(records, "250403")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.WARNING
    assert record.sleuteltype == "oprf_secret"  # type: ignore[attr-defined]
    assert (
        record.organisatie_oin  # type: ignore[attr-defined]
        == persisted_organization.external_id.value
    )
    assert record.vernietigde_versie == 7  # type: ignore[attr-defined]
    assert not _events(records, "250406")


def test_cleanup_destroy_failure_emits_operation_failed(
    record_logs: RecordLogs,
    database: Database,
    persisted_organization: OrganizationEntity,
) -> None:
    records = record_logs("app.services.hsm_key_cleanup_service")
    _add_expired_version(database, persisted_organization, version=7)

    with patch(
        "app.services.hsm.client.requests.post",
        return_value=_hsm_response(None, status_code=503),
    ):
        cleaned = _cleanup_service(database).cleanup_expired_keys()

    assert cleaned == 0
    events = _events(records, "250406")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.ERROR
    assert record.operation_type == "destroy"  # type: ignore[attr-defined]
    assert record.error_reason == "HTTPError"  # type: ignore[attr-defined]
    assert record.exc_info is not None
    assert not _events(records, "250403")


def _auth_headers(valid_headers: dict[str, str], org_oin: Oin) -> dict[str, str]:
    return {**valid_headers, "x-gf-sub": org_oin.value}


def test_register_public_key_emits_registered(
    record_logs: RecordLogs,
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    records = record_logs("app.services.organization_public_key_service")
    oin = persisted_organization.external_id
    private_key, _ = generate_rsa_keypair()

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": create_signed_jws(private_key, oin)},
        headers=_auth_headers(valid_headers, oin),
    )

    assert response.status_code == 201
    events = _events(records, "250404")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.organisatie_oin == oin.value  # type: ignore[attr-defined]
    assert record.key_algoritme == "RSA"  # type: ignore[attr-defined]
    assert record.key_lengte == 2048  # type: ignore[attr-defined]
    assert record.key_versie == response.json()["jwk"]["kid"]  # type: ignore[attr-defined]
    assert not _events(records, "250405")


def test_update_public_key_emits_registered(
    record_logs: RecordLogs,
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    records = record_logs("app.services.organization_public_key_service")
    oin = persisted_organization.external_id
    headers = _auth_headers(valid_headers, oin)
    private_key, _ = generate_rsa_keypair()
    created = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": create_signed_jws(private_key, oin)},
        headers=headers,
    ).json()
    new_private_key, _ = generate_rsa_keypair()

    response = client.put(
        f"/administration/keys/{created['id']}",
        json={"domains": ["nvi"], "jws": create_signed_jws(new_private_key, oin)},
        headers=headers,
    )

    assert response.status_code == 200
    events = _events(records, "250404")
    assert len(events) == 2
    assert events[1].key_versie == response.json()["jwk"]["kid"]  # type: ignore[attr-defined]
    assert events[1].key_versie != events[0].key_versie  # type: ignore[attr-defined]


def test_register_public_key_for_other_oin_emits_rejected(
    record_logs: RecordLogs,
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    records = record_logs("app.services.organization_public_key_service")
    oin = persisted_organization.external_id
    private_key, _ = generate_rsa_keypair()
    # Proof of possession is bound to the wrong organisation.
    jws = create_signed_jws(private_key, Oin("00000099000000004000"))

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": jws},
        headers=_auth_headers(valid_headers, oin),
    )

    assert response.status_code == 422
    events = _events(records, "250405")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.WARNING
    assert record.organisatie_oin == oin.value  # type: ignore[attr-defined]
    assert record.key_algoritme == "RSA"  # type: ignore[attr-defined]
    assert record.rejection_reason == "Unauthorized for supplied `oin`"  # type: ignore[attr-defined]
    assert not _events(records, "250404")


def test_register_malformed_jws_emits_rejected_without_algorithm(
    record_logs: RecordLogs,
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    records = record_logs("app.services.organization_public_key_service")
    oin = persisted_organization.external_id

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": "not-a-jws" * 8},
        headers=_auth_headers(valid_headers, oin),
    )

    assert response.status_code == 422
    events = _events(records, "250405")
    assert len(events) == 1
    assert events[0].key_algoritme is None  # type: ignore[attr-defined]
    assert events[0].rejection_reason == "JWS invalid"  # type: ignore[attr-defined]


def test_register_public_key_duplicate_domain_emits_rejected(
    record_logs: RecordLogs,
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    records = record_logs("app.services.organization_public_key_service")
    oin = persisted_organization.external_id
    headers = _auth_headers(valid_headers, oin)
    for _ in range(2):
        private_key, _ = generate_rsa_keypair()
        response = client.post(
            "/administration/keys",
            json={"domains": ["nvi"], "jws": create_signed_jws(private_key, oin)},
            headers=headers,
        )

    assert response.status_code == 409
    assert len(_events(records, "250404")) == 1
    rejected = _events(records, "250405")
    assert len(rejected) == 1
    assert rejected[0].key_algoritme == "RSA"  # type: ignore[attr-defined]
    assert rejected[0].rejection_reason == "domain already registered"  # type: ignore[attr-defined]


def test_oprf_label_is_the_same_for_request_and_stored_oin() -> None:
    """The evaluator builds the label from the recipient in the request (a
    RecipientOrganizationOin, whose str() carries the "oin:" prefix) and the
    cleanup builds it from the organization stored in the database (a plain
    Oin). Both must address the same HSM object."""
    from_request = OprfHsmKeyLabel(RecipientOrganizationOin(f"oin:{TEST_OIN}"), 3)
    from_database = OprfHsmKeyLabel(TEST_OIN, 3)

    assert str(from_request) == str(from_database) == f"oin-{TEST_OIN.value}-oprf-v3"
    assert "oin:" not in str(from_request)
