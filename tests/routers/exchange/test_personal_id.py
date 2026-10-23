from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from app.db.models.organization import OrganizationEntity
from app.exceptions.pseudonym import (
    CryptoFailureError,
    InvalidPseudonymError,
    PseudonymVersionDestroyedError,
)
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversedPseudonym
from tests.conftest import setup_org_and_key


@pytest.fixture()
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
    )
    mock_reverse.return_value = mock_reversed

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

    assert response.status_code == 201
    assert response.headers["content-type"] == "application/jwe"
    assert response.content


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
    mock_reverse.side_effect = InvalidPseudonymError()

    request_body = {
        "reversiblePseudonym": "invalid_pseudonym",
        "recipientOrganization": f"oin:{org_with_personal_id_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    response = client.post(
        "/exchange/personal-id",
        json=request_body,
        headers=valid_personal_id_headers,
    )

    assert response.status_code == 400


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
    mock_reverse.side_effect = PseudonymVersionDestroyedError()

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

    assert response.status_code == 410
