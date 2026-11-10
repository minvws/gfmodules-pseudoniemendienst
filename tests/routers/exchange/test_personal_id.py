from unittest.mock import MagicMock, patch

import pytest
from gfmodules.logging.testing import assert_event_emitted, capture_records
from starlette.testclient import TestClient

from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.exceptions.pseudonym import (
    CryptoFailureError,
    InvalidPseudonymError,
    PseudonymVersionDestroyedError,
)
from app.logging.events import Log
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversedPseudonym
from tests.conftest import create_organization, setup_org_and_key

LOGGER = "app.routers.exchange.personal_id"


@pytest.fixture
def valid_personal_id_headers(
    valid_organization_id_2: Oin,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    expected_audiences: list[str],
) -> dict[str, str]:
    return {
        "x-gf-sub": valid_organization_id_2.value,
        "x-gf-act-sub": valid_client_organization_id.value,
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": "".join(expected_audiences),
        "x-gf-scope": AuthorizationScope.PSEUDONYM.value,
    }


@patch("app.services.reversible.service.ReversiblePseudonymService.reverse")
def test_post_personal_id_should_return_jwe(
    mock_reverse: MagicMock,
    client: TestClient,
    org_with_personal_id_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    mock_personal_id: PersonalId,
    valid_personal_id_headers: dict[str, str],
    valid_client_organization_id: Oin,
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_personal_id_type,
        domains=["test_scope"],
    )

    # Mock the service to return a valid reversed pseudonym
    mock_reversed = ReversedPseudonym(
        personal_id=mock_personal_id,
        recipient_organization=f"oin:{org_with_personal_id_type.external_id.value}",
        recipient_scope="test_scope",
        version=1,
        current_version=1,
    )
    mock_reverse.return_value = mock_reversed

    request_body = {
        "reversiblePseudonym": "pseudonym:reversible:dGVzdA==",
        "recipientOrganization": f"oin:{org_with_personal_id_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    with capture_records(LOGGER) as captured:
        response = client.post(
            "/exchange/personal-id",
            json=request_body,
            headers=valid_personal_id_headers,
        )

    assert response.status_code == 201
    assert response.headers["content-type"] == "application/jwe"
    assert response.content
    exchanged = assert_event_emitted(
        captured,
        Log.PERSONAL_ID_EXCHANGED,
        acting_organization_identifier=str(valid_client_organization_id),
        represented_organization_identifier=str(org_with_personal_id_type.external_id),
        recipient_organization_identifier=request_body["recipientOrganization"],
        domain="test_scope",
        source_artifact_type="reversible_pseudonym",
        artifact_version=1,
        key_version=1,
    )
    assert exchanged.message["recipient_pubkey_id"]
    assert not captured.for_event(Log.PERSONAL_ID_EXCHANGED_FROM_GRACE_VERSION)


@patch("app.services.reversible.service.ReversiblePseudonymService.reverse")
def test_post_personal_id_should_audit_a_pseudonym_from_a_version_in_grace(
    mock_reverse: MagicMock,
    client: TestClient,
    org_with_personal_id_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    mock_personal_id: PersonalId,
    valid_personal_id_headers: dict[str, str],
) -> None:
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_personal_id_type,
        domains=["test_scope"],
    )
    mock_reverse.return_value = ReversedPseudonym(
        personal_id=mock_personal_id,
        recipient_organization=f"oin:{org_with_personal_id_type.external_id.value}",
        recipient_scope="test_scope",
        version=1,
        current_version=2,
    )

    request_body = {
        "reversiblePseudonym": "pseudonym:reversible:dGVzdA==",
        "recipientOrganization": f"oin:{org_with_personal_id_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    with capture_records(LOGGER) as captured:
        response = client.post(
            "/exchange/personal-id",
            json=request_body,
            headers=valid_personal_id_headers,
        )

    assert response.status_code == 201
    assert_event_emitted(
        captured, Log.PERSONAL_ID_EXCHANGED, artifact_version=1, key_version=2
    )
    assert_event_emitted(
        captured,
        Log.PERSONAL_ID_EXCHANGED_FROM_GRACE_VERSION,
        artifact_version=1,
        key_version=2,
    )


@patch("app.services.reversible.service.ReversiblePseudonymService.reverse")
def test_post_personal_id_should_return_500_when_crypto_failure(
    mock_reverse: MagicMock,
    client: TestClient,
    org_with_personal_id_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    valid_personal_id_headers: dict[str, str],
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_personal_id_type,
        domains=["test_scope"],
    )

    # Mock the service to raise an error
    mock_reverse.side_effect = CryptoFailureError()

    request_body = {
        "reversiblePseudonym": "pseudonym:reversible:dGVzdA==",
        "recipientOrganization": f"oin:{org_with_personal_id_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    response = client.post(
        "/exchange/personal-id",
        json=request_body,
        headers=valid_personal_id_headers,
    )

    assert response.status_code == 500


@patch("app.services.reversible.service.ReversiblePseudonymService.reverse")
def test_post_personal_id_should_return_400_when_invalid_pseudonym(
    mock_reverse: MagicMock,
    client: TestClient,
    org_with_personal_id_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    valid_personal_id_headers: dict[str, str],
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_personal_id_type,
        domains=["test_scope"],
    )

    # Mock the service to raise an error
    error = InvalidPseudonymError()
    error.key_version = 1
    mock_reverse.side_effect = error

    request_body = {
        "reversiblePseudonym": "invalid_pseudonym",
        "recipientOrganization": f"oin:{org_with_personal_id_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    with capture_records(LOGGER) as captured:
        response = client.post(
            "/exchange/personal-id",
            json=request_body,
            headers=valid_personal_id_headers,
        )

    assert response.status_code == 400
    assert_event_emitted(
        captured,
        Log.PERSONAL_ID_EXCHANGE_FAILED,
        error_type="invalid_pseudonym",
        artifact_version=1,
    )
    assert not captured.for_event(Log.PERSONAL_ID_EXCHANGED)


def test_post_personal_id_should_return_403_when_missing_scope(
    client: TestClient,
    org_with_personal_id_type: OrganizationEntity,
    valid_personal_id_headers: dict[str, str],
) -> None:
    # Create headers WITHOUT the required scope
    headers = {**valid_personal_id_headers}
    del headers["x-gf-scope"]

    request_body = {
        "reversiblePseudonym": "pseudonym:reversible:dGVzdA==",
        "recipientOrganization": f"oin:{org_with_personal_id_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    response = client.post(
        "/exchange/personal-id",
        json=request_body,
        headers=headers,
    )

    assert response.status_code == 403


def test_post_personal_id_should_return_403_when_sender_may_not_request_it(
    client: TestClient,
    org_with_reversible_pseudonym_type: OrganizationEntity,
    valid_personal_id_headers: dict[str, str],
) -> None:
    request_body = {
        "reversiblePseudonym": "pseudonym:reversible:dGVzdA==",
        "recipientOrganization": f"oin:{org_with_reversible_pseudonym_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    with capture_records(LOGGER) as captured:
        response = client.post(
            "/exchange/personal-id",
            json=request_body,
            headers=valid_personal_id_headers,
        )

    assert response.status_code == 403
    assert_event_emitted(
        captured,
        Log.PERSONAL_ID_EXCHANGE_REFUSED,
        missing_flag="request_personal_id",
    )
    assert not captured.for_event(Log.AUTHORIZATION_DENIED)


@pytest.mark.parametrize(
    "recipient_exists", [False, True], ids=["unknown", "not-allowed-to-receive"]
)
def test_post_personal_id_should_return_404_when_recipient_may_not_receive_it(
    recipient_exists: bool,
    client: TestClient,
    db_session: DbSession,
    org_with_personal_id_type: OrganizationEntity,
    valid_organization_id: Oin,
    valid_personal_id_headers: dict[str, str],
) -> None:
    if recipient_exists:
        create_organization(db_session, valid_organization_id)

    request_body = {
        "reversiblePseudonym": "pseudonym:reversible:dGVzdA==",
        "recipientOrganization": f"oin:{valid_organization_id.value}",
        "recipientScope": "test_scope",
    }

    with capture_records(LOGGER) as captured:
        response = client.post(
            "/exchange/personal-id",
            json=request_body,
            headers=valid_personal_id_headers,
        )

    assert response.status_code == 404
    assert_event_emitted(
        captured,
        Log.PERSONAL_ID_EXCHANGE_REFUSED,
        missing_flag="receive_personal_id",
    )
    assert not captured.for_event(Log.PERSONAL_ID_EXCHANGED)


def test_post_personal_id_should_return_404_when_no_public_key_for_scope(
    client: TestClient,
    org_with_personal_id_type: OrganizationEntity,
    valid_personal_id_headers: dict[str, str],
) -> None:
    # Don't set up a public key for the scope - this should trigger 404
    request_body = {
        "reversiblePseudonym": "pseudonym:reversible:dGVzdA==",
        "recipientOrganization": f"oin:{org_with_personal_id_type.external_id.value}",
        "recipientScope": "non_existent_scope",
    }

    response = client.post(
        "/exchange/personal-id",
        json=request_body,
        headers=valid_personal_id_headers,
    )

    assert response.status_code == 404


@patch("app.services.reversible.service.ReversiblePseudonymService.reverse")
def test_post_personal_id_should_return_410_when_key_version_destroyed(
    mock_reverse: MagicMock,
    client: TestClient,
    org_with_personal_id_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    valid_personal_id_headers: dict[str, str],
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_personal_id_type,
        domains=["test_scope"],
    )

    # Mock the service to raise an error
    error = PseudonymVersionDestroyedError()
    error.key_version = 1
    mock_reverse.side_effect = error

    request_body = {
        "reversiblePseudonym": "pseudonym:reversible:dGVzdA==",
        "recipientOrganization": f"oin:{org_with_personal_id_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    with capture_records(LOGGER) as captured:
        response = client.post(
            "/exchange/personal-id",
            json=request_body,
            headers=valid_personal_id_headers,
        )

    assert response.status_code == 410
    assert_event_emitted(
        captured,
        Log.PERSONAL_ID_EXCHANGE_FAILED,
        error_type="version_destroyed",
        artifact_version=1,
    )
