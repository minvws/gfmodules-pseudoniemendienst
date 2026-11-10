"""Integration tests for HSM key event logging.

These tests verify that the PRS-KEY events (issue 1039) are emitted correctly
when interacting with the HSM, including key generation, rotation, destruction,
and public key registration.
"""

import base64
import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests
from gfmodules.logging import LogEvent, LoggingStreams
from jwcrypto.jwk import JWK
from starlette.testclient import TestClient

from app.db.db import Database
from app.db.models import HsmKeyVersionEntity, OrganizationEntity
from app.logging.events import Log
from app.models.oin import Oin, RecipientOrganizationOin
from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.oprf.evaluators import HsmOprfEvaluator, OprfHsmKeyLabel
from tests.conftest import (
    create_signed_jws,
    generate_rsa_keypair,
)

# Constants for logger names
EVALUATOR_LOGGER = "app.services.oprf.evaluators"
HSM_CLIENT_LOGGER = "app.services.hsm.client"
KEY_CLEANUP_SERVICE_LOGGER = "app.services.hsm_key_cleanup_service"
ORG_PUBKEY_SERVICE_LOGGER = "app.services.organization_public_key_service"


# Helper to filter log records by event_id
def _events(records: list[logging.LogRecord], event_id: str) -> list[logging.LogRecord]:
    """Filters log records to only those matching the given event_id."""
    return [r for r in records if getattr(r, "event_id", None) == event_id]


def _hsm_response(payload: object, status_code: int = 200) -> MagicMock:
    """Creates a mock HSM HTTP response with the given payload and status code."""
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError("boom")
    return response


def _hsm_no_such_key(oin: Oin) -> MagicMock:
    """Mocks HSM response when a key does not exist (422)."""
    return _hsm_response({"error_description": f"OPRF key '{oin}' not found"}, 422)


def _add_expired_version(
    database: Database, organization: OrganizationEntity, version: int
) -> None:
    """Helper to add an expired HSM key version to the database."""
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


def _auth_headers(valid_headers: dict[str, str], org_oin: Oin) -> dict[str, str]:
    """Helper to create headers with the given organization OIN as the subject."""
    return {**valid_headers, "x-gf-sub": org_oin.value}


# ==================== TESTS ====================


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
        (Log.DECRYPT_PUBKEY_DELETED, "250407", logging.WARNING),
    ],
)
def test_key_events_match_logging_spec(
    event: LogEvent, expected_id: str, expected_level: int
) -> None:
    """Tests that all PRS-KEY events match the logging specification."""
    assert event.event_id == expected_id
    assert event.level == expected_level
    assert event.streams == (LoggingStreams.APP, LoggingStreams.SIEM)
    # "Stroom 3" is always a subset of "stroom 2".
    assert set(event.fields[LoggingStreams.SIEM]) <= set(
        event.fields[LoggingStreams.APP]
    )


def test_lazy_oprf_key_generation_emits_key_generated(
    record_logs: Callable[[str], list[logging.LogRecord]],
    caplog: pytest.LogCaptureFixture,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that lazy OPRF key generation emits the KEY_GENERATED event (250400)."""
    records = record_logs(EVALUATOR_LOGGER)

    # Mock HSM responses:
    # 1. First call: Key does not exist (422)
    # 2. Second call: Key generation succeeds (200)
    # 3. Third call: OPRF evaluation succeeds (200)
    with (
        caplog.at_level(logging.INFO, logger=EVALUATOR_LOGGER),
        patch(
            "requests.Session.request",
            side_effect=[
                _hsm_no_such_key(
                    persisted_organization.external_id
                ),  # oprf_evaluate: key does not exist yet
                _hsm_response({"result": "ok"}),  # keygen
                _hsm_response({"result": "AAAA"}),  # oprf_evaluate, retried
            ],
        ),
    ):
        hsm_oprf_evaluator.evaluate(persisted_organization.external_id, b"blinded")

    events = _events(records, Log.KEY_GENERATED.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.key_type == "oprf_secret"  # type: ignore[attr-defined]
    assert record.organization_identifier == persisted_organization.external_id.value  # type: ignore[attr-defined]
    assert record.secret_id == str(  # type: ignore[attr-defined]
        OprfHsmKeyLabel(persisted_organization.external_id, 1)
    )
    assert record.key_version == 1  # type: ignore[attr-defined]
    assert not _events(records, Log.HSM_OPERATION_FAILED.event_id)


def test_cleanup_emits_key_version_destroyed(
    record_logs: Callable[[str], list[logging.LogRecord]],
    database: Database,
    persisted_organization: OrganizationEntity,
    hsm_key_cleanup_service: HsmKeyCleanupService,
) -> None:
    """Tests that cleanup of expired keys emits KEY_VERSION_DESTROYED (250403)."""
    records = record_logs(KEY_CLEANUP_SERVICE_LOGGER)
    _add_expired_version(database, persisted_organization, version=7)

    with patch(
        "requests.Session.request",
        return_value=_hsm_response({"objects": [{"label": "x"}]}),
    ):
        cleaned = hsm_key_cleanup_service.cleanup_expired_keys()

    assert cleaned == 1
    # The AES and HMAC reversible keys share one event.
    events = _events(records, Log.KEY_VERSION_DESTROYED.event_id)
    assert sorted(r.key_type for r in events) == [  # type: ignore[attr-defined]
        "irreversible_pseudonym_key",
        "oprf_secret",
        "reversible_pseudonym_key",
    ]
    for record in events:
        assert record.levelno == logging.WARNING
        assert (
            record.organization_identifier  # type: ignore[attr-defined]
            == persisted_organization.external_id.value
        )
        assert record.destroyed_version == 7  # type: ignore[attr-defined]
    assert not _events(records, Log.HSM_OPERATION_FAILED.event_id)


def test_register_public_key_emits_registered(
    record_logs: Callable[[str], list[logging.LogRecord]],
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    """Tests that registering a public key emits DECRYPT_PUBKEY_REGISTERED (250404)."""
    records = record_logs(ORG_PUBKEY_SERVICE_LOGGER)
    oin = persisted_organization.external_id
    private_key, _ = generate_rsa_keypair()

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": create_signed_jws(private_key, oin)},
        headers=_auth_headers(valid_headers, oin),
    )

    assert response.status_code == 201
    events = _events(records, Log.DECRYPT_PUBKEY_REGISTERED.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.organization_identifier == oin.value  # type: ignore[attr-defined]
    assert record.key_algorithm == "RSA"  # type: ignore[attr-defined]
    assert record.key_length == 3072  # type: ignore[attr-defined]
    assert (
        record.key_version  # type: ignore[attr-defined]
        == response.json()["jwk"]["kid"]
    )
    assert not _events(records, Log.DECRYPT_PUBKEY_REJECTED.event_id)


def test_delete_public_key_emits_deleted_once(
    record_logs: Callable[[str], list[logging.LogRecord]],
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

    first = client.delete(f"/administration/keys/{created['id']}", headers=headers)
    again = client.delete(f"/administration/keys/{created['id']}", headers=headers)

    assert (first.status_code, again.status_code) == (200, 404)
    events = _events(records, "250407")
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.WARNING
    assert record.organization_identifier == oin.value  # type: ignore[attr-defined]
    assert record.key_version == created["jwk"]["kid"]  # type: ignore[attr-defined]


def test_update_public_key_emits_registered(
    record_logs: Callable[[str], list[logging.LogRecord]],
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    """Tests that updating a public key emits DECRYPT_PUBKEY_REGISTERED (250404)."""
    records = record_logs(ORG_PUBKEY_SERVICE_LOGGER)
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
    events = _events(records, Log.DECRYPT_PUBKEY_REGISTERED.event_id)
    assert len(events) == 2
    assert (
        events[1].key_version  # type: ignore[attr-defined]
        == response.json()["jwk"]["kid"]
    )
    assert events[1].key_version != events[0].key_version  # type: ignore[attr-defined]


def test_register_public_key_for_other_oin_emits_rejected(
    record_logs: Callable[[str], list[logging.LogRecord]],
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
    valid_organization_id_2: Oin,
) -> None:
    """Tests that registering a public key for a different OIN emits DECRYPT_PUBKEY_REJECTED (250405)."""
    records = record_logs(ORG_PUBKEY_SERVICE_LOGGER)
    oin = persisted_organization.external_id
    private_key, _ = generate_rsa_keypair()
    # Proof of possession is bound to the wrong organization (valid_organization_id_2).
    jws = create_signed_jws(private_key, valid_organization_id_2)

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": jws},
        headers=_auth_headers(valid_headers, oin),
    )

    assert response.status_code == 422
    events = _events(records, Log.DECRYPT_PUBKEY_REJECTED.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.WARNING
    assert record.organization_identifier == oin.value  # type: ignore[attr-defined]
    assert record.key_algorithm == "RSA"  # type: ignore[attr-defined]
    assert record.rejection_reason == "Unauthorized for supplied `oin`"  # type: ignore[attr-defined]
    assert not _events(records, Log.DECRYPT_PUBKEY_REGISTERED.event_id)


def test_register_non_rsa_public_key_emits_rejected(
    record_logs: Callable[[str], list[logging.LogRecord]],
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    """Tests that registering a non-RSA public key emits DECRYPT_PUBKEY_REJECTED (250405)."""
    records = record_logs(ORG_PUBKEY_SERVICE_LOGGER)
    oin = persisted_organization.external_id
    # Generate an EC key (not RSA)
    private_key = (
        JWK.generate(kty="EC", crv="P-256")
        .export_to_pem(private_key=True, password=None)
        .decode()
    )

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": create_signed_jws(private_key, oin, "ES256")},
        headers=_auth_headers(valid_headers, oin),
    )

    assert response.status_code == 422
    events = _events(records, Log.DECRYPT_PUBKEY_REJECTED.event_id)
    assert len(events) == 1
    assert events[0].key_algorithm == "EC/P-256"  # type: ignore
    assert events[0].rejection_reason == "'jwk' must be an RSA key"  # type: ignore
    assert not _events(records, Log.DECRYPT_PUBKEY_REGISTERED.event_id)


def test_register_malformed_jws_emits_rejected_without_algorithm(
    record_logs: Callable[[str], list[logging.LogRecord]],
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    """Tests that registering a malformed JWS emits DECRYPT_PUBKEY_REJECTED (250405)."""
    records = record_logs(ORG_PUBKEY_SERVICE_LOGGER)
    oin = persisted_organization.external_id

    response = client.post(
        "/administration/keys",
        json={"domains": ["nvi"], "jws": "not-a-jws" * 8},
        headers=_auth_headers(valid_headers, oin),
    )

    assert response.status_code == 422
    events = _events(records, Log.DECRYPT_PUBKEY_REJECTED.event_id)
    assert len(events) == 1
    assert events[0].key_algorithm is None  # type: ignore[attr-defined]
    assert events[0].rejection_reason == "JWS invalid"  # type: ignore


def test_register_public_key_duplicate_domain_emits_rejected(
    record_logs: Callable[[str], list[logging.LogRecord]],
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    """Tests that registering a public key for a duplicate domain emits DECRYPT_PUBKEY_REJECTED (250405)."""
    records = record_logs(ORG_PUBKEY_SERVICE_LOGGER)
    oin = persisted_organization.external_id
    headers = _auth_headers(valid_headers, oin)
    # Register two keys for the same domain
    for _ in range(2):
        private_key, _ = generate_rsa_keypair()
        response = client.post(
            "/administration/keys",
            json={"domains": ["nvi"], "jws": create_signed_jws(private_key, oin)},
            headers=headers,
        )

    assert response.status_code == 409
    assert len(_events(records, Log.DECRYPT_PUBKEY_REGISTERED.event_id)) == 1
    rejected = _events(records, Log.DECRYPT_PUBKEY_REJECTED.event_id)
    assert len(rejected) == 1
    assert rejected[0].key_algorithm == "RSA"  # type: ignore[attr-defined]
    assert rejected[0].rejection_reason == "domain already registered"  # type: ignore


def test_oprf_label_is_the_same_for_request_and_stored_oin(
    valid_organization_id_2: Oin,
) -> None:
    """Tests that OPRF labels are consistent between request OINs and stored OINs."""
    from_request = OprfHsmKeyLabel(
        RecipientOrganizationOin(f"oin:{valid_organization_id_2}"), 3
    )
    from_database = OprfHsmKeyLabel(valid_organization_id_2, 3)

    assert (
        str(from_request)
        == str(from_database)
        == f"oin-{valid_organization_id_2.value}-oprf-v3"
    )
    assert "oin:" not in str(from_request)


def test_cleanup_key_version_destroyed_names_the_destroyed_key_type(
    record_logs: Callable[[str], list[logging.LogRecord]],
    database: Database,
    persisted_organization: OrganizationEntity,
    hsm_key_cleanup_service: HsmKeyCleanupService,
) -> None:
    """Tests that cleanup only emits events for the key types that were actually destroyed."""
    records = record_logs(KEY_CLEANUP_SERVICE_LOGGER)
    _add_expired_version(database, persisted_organization, version=7)

    def post(
        method: str, url: str, json: dict[str, str], **kwargs: object
    ) -> MagicMock:
        # Only return a key for irreversible pseudonyms (not OPRF)
        present = "-irp-" in json["label"]
        return _hsm_response({"objects": [{"label": "x"}] if present else []})

    with patch("requests.Session.request", side_effect=post):
        cleaned = hsm_key_cleanup_service.cleanup_expired_keys()

    assert cleaned == 1
    events = _events(records, Log.KEY_VERSION_DESTROYED.event_id)
    assert len(events) == 1
    assert events[0].key_type == "irreversible_pseudonym_key"  # type: ignore


def test_cleanup_destroy_failure_emits_operation_failed(
    record_logs: Callable[[str], list[logging.LogRecord]],
    database: Database,
    persisted_organization: OrganizationEntity,
    hsm_key_cleanup_service: HsmKeyCleanupService,
) -> None:
    """Tests that a cleanup failure emits HSM_OPERATION_FAILED (250406)."""
    records = record_logs(KEY_CLEANUP_SERVICE_LOGGER)
    _add_expired_version(database, persisted_organization, version=7)

    with patch(
        "requests.Session.request",
        return_value=_hsm_response(None, status_code=503),
    ):
        cleaned = hsm_key_cleanup_service.cleanup_expired_keys()

    assert cleaned == 0
    events = _events(records, Log.HSM_OPERATION_FAILED.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.ERROR
    assert record.operation_type == "destroy"  # type: ignore[attr-defined]
    assert record.error_reason == "HTTPError"  # type: ignore[attr-defined]
    assert record.exc_info is not None
    assert not _events(records, Log.KEY_VERSION_DESTROYED.event_id)


def test_existing_oprf_key_does_not_emit_key_generated(
    record_logs: Callable[[str], list[logging.LogRecord]],
    caplog: pytest.LogCaptureFixture,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that an existing OPRF key does not emit KEY_GENERATED event."""
    records = record_logs(EVALUATOR_LOGGER)

    with (
        caplog.at_level(logging.INFO, logger=EVALUATOR_LOGGER),
        patch(
            "requests.Session.request",
            side_effect=[_hsm_response({"result": "AAAA"})],  # Key exists
        ),
    ):
        hsm_oprf_evaluator.evaluate(persisted_organization.external_id, b"blinded")

    assert not _events(records, Log.KEY_GENERATED.event_id)


def test_oprf_key_created_by_another_instance_emits_nothing(
    record_logs: Callable[[str], list[logging.LogRecord]],
    caplog: pytest.LogCaptureFixture,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that a race condition in key creation (another instance created the key)
    does not emit KEY_GENERATED or HSM_OPERATION_FAILED events."""
    records = record_logs(EVALUATOR_LOGGER)
    client_records = record_logs(HSM_CLIENT_LOGGER)

    # Mock HSM responses:
    # 1. First call: Key does not exist (422)
    # 2. Second call: Key already exists (422, "Object already exists")
    # 3. Third call: OPRF evaluation succeeds (200)
    with (
        caplog.at_level(logging.INFO, logger=EVALUATOR_LOGGER),
        patch(
            "requests.Session.request",
            side_effect=[
                _hsm_no_such_key(persisted_organization.external_id),
                _hsm_response({"error_description": "Object already exists"}, 422),
                _hsm_response({"result": "AAAA"}),
            ],
        ),
    ):
        result = hsm_oprf_evaluator.evaluate(
            persisted_organization.external_id, b"blinded"
        )

    assert result == {1: base64.b64decode("AAAA")}
    assert not _events(records, Log.KEY_GENERATED.event_id)
    assert not _events(client_records, Log.HSM_OPERATION_FAILED.event_id)


def test_hsm_http_error_emits_operation_failed(
    record_logs: Callable[[str], list[logging.LogRecord]],
    hsm_oprf_evaluator: HsmOprfEvaluator,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that an HSM HTTP error emits the HSM_OPERATION_FAILED event (250406)."""
    records = record_logs(HSM_CLIENT_LOGGER)

    with (
        patch(
            "requests.Session.request",
            return_value=_hsm_response(None, status_code=500),
        ),
        pytest.raises(requests.HTTPError),
    ):
        hsm_oprf_evaluator.evaluate(persisted_organization.external_id, b"blinded")

    events = _events(records, Log.HSM_OPERATION_FAILED.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.ERROR
    assert record.operation_type == "oprf_evaluate"  # type: ignore[attr-defined]
    assert record.error_reason == "http_500"  # type: ignore[attr-defined]
    assert record.exc_info is not None
    # PRS-SYS-006 is for an unreachable HSM only.
    assert not _events(records, "270406")


def test_hsm_keygen_without_result_emits_operation_failed(
    record_logs: Callable[[str], list[logging.LogRecord]],
    hsm_oprf_evaluator: HsmOprfEvaluator,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that an HSM keygen response without a result emits HSM_OPERATION_FAILED (250406)."""
    records = record_logs(HSM_CLIENT_LOGGER)
    evaluator_records = record_logs(EVALUATOR_LOGGER)

    with (
        patch(
            "requests.Session.request",
            side_effect=[
                _hsm_no_such_key(persisted_organization.external_id),
                # Keygen fails without result
                _hsm_response({"error": "denied"}),
            ],
        ),
        pytest.raises(ValueError),
    ):
        hsm_oprf_evaluator.evaluate(persisted_organization.external_id, b"blinded")

    events = _events(records, Log.HSM_OPERATION_FAILED.event_id)
    assert len(events) == 1
    assert events[0].operation_type == "keygen"  # type: ignore
    assert events[0].error_reason == "no_result_in_response"  # type: ignore
    assert not _events(evaluator_records, Log.KEY_GENERATED.event_id)


def test_create_key_version_emits_rotation_started(
    record_logs: Callable[[str], list[logging.LogRecord]],
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    """Tests that creating a new key version emits KEY_ROTATION_STARTED (250401)."""
    records = record_logs("app.services.hsm_key_version_service")

    response = client.post("/administration/key-versions", headers=valid_headers)

    assert response.status_code == 201
    events = _events(records, Log.KEY_ROTATION_STARTED.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.WARNING
    assert record.key_type == "oprf_secret"  # type: ignore[attr-defined]
    assert (
        record.organization_identifier  # type: ignore[attr-defined]
        == persisted_organization.external_id.value
    )
    assert record.previous_version == 1  # type: ignore[attr-defined]
    assert record.new_version == 2  # type: ignore[attr-defined]


def test_update_key_version_with_until_dt_emits_grace_started(
    record_logs: Callable[[str], list[logging.LogRecord]],
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    """Tests that updating a key version with an until_dt emits KEY_GRACE_STARTED (250402)."""
    records = record_logs("app.services.hsm_key_version_service")
    # Create a new key version first
    created = client.post("/administration/key-versions", headers=valid_headers).json()
    until_dt = datetime.now(timezone.utc) + timedelta(days=30)

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": until_dt.isoformat()},
        headers=valid_headers,
    )

    assert response.status_code == 200
    events = _events(records, Log.KEY_GRACE_STARTED.event_id)
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert record.key_type == "oprf_secret"  # type: ignore[attr-defined]
    assert (
        record.organization_identifier  # type: ignore[attr-defined]
        == persisted_organization.external_id.value
    )
    assert record.previous_version == created["version"]  # type: ignore
    assert record.grace_end == until_dt.isoformat()  # type: ignore
    grace_start = datetime.fromisoformat(record.grace_start)  # type: ignore[attr-defined]
    assert grace_start <= datetime.now(timezone.utc)


def test_update_key_version_clearing_until_dt_emits_nothing(
    record_logs: Callable[[str], list[logging.LogRecord]],
    client: TestClient,
    persisted_organization: OrganizationEntity,
    valid_headers: dict[str, str],
) -> None:
    """Tests that clearing the until_dt of a key version does not emit KEY_GRACE_STARTED."""
    records = record_logs(KEY_CLEANUP_SERVICE_LOGGER)
    # Create a new key version first
    created = client.post("/administration/key-versions", headers=valid_headers).json()

    response = client.put(
        f"/administration/key-versions/{created['id']}",
        json={"until_dt": None},
        headers=valid_headers,
    )

    assert response.status_code == 200
    assert not _events(records, Log.KEY_GRACE_STARTED.event_id)
