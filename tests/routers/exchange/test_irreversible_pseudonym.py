from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from app.db.models.organization import OrganizationEntity
from app.exceptions.pseudonym import (
    CryptoFailureError,
    HsmUnreachableError,
    PseudonymVersionDestroyedError,
)
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.services.irreversible.service import IrreversiblePseudonym
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversedPseudonym
from tests.conftest import setup_org_and_key


@pytest.fixture()
def valid_irreversible_pseudonym_headers(
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


def test_post_irreversible_pseudonym_should_return_jwe_with_personal_id(
    client: TestClient,
    org_with_irreversible_pseudonym_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    mock_personal_id: PersonalId,
    valid_irreversible_pseudonym_headers: dict[str, str],
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_irreversible_pseudonym_type,
        domains=["test_scope"],
    )

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org_with_irreversible_pseudonym_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    # Mock the service to return a valid pseudonym
    with patch(
        "app.services.irreversible.service.IrreversiblePseudonymService.generate"
    ) as mock_generate:
        mock_pseudonym = IrreversiblePseudonym(
            value="test_pseudonym_value",
            version=1,
            older=(),
        )
        mock_generate.return_value = mock_pseudonym

        response = client.post(
            "/exchange/irreversible-pseudonym",
            json=request_body,
            headers=valid_irreversible_pseudonym_headers,
        )

        assert response.status_code == 201
        assert response.headers["content-type"] == "application/jwe"
        assert response.content


@patch("app.services.irreversible.service.IrreversiblePseudonymService.generate")
@patch("app.services.reversible.service.ReversiblePseudonymService.reverse")
def test_post_irreversible_pseudonym_should_return_jwe_with_reversible_pseudonym(
    mock_reverse: MagicMock,
    mock_generate: MagicMock,
    client: TestClient,
    org_with_irreversible_pseudonym_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    mock_personal_id: PersonalId,
    valid_irreversible_pseudonym_headers: dict[str, str],
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_irreversible_pseudonym_type,
        domains=["test_scope"],
    )

    # Create a valid reversible pseudonym
    reversible_pseudonym = "pseudonym:reversible:dGVzdA=="

    request_body = {
        "reversiblePseudonym": reversible_pseudonym,
        "recipientOrganization": f"oin:{org_with_irreversible_pseudonym_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    # Set up mock return values
    mock_reverse.return_value = ReversedPseudonym(
        personal_id=mock_personal_id,
        recipient_organization=f"oin:{org_with_irreversible_pseudonym_type.external_id.value}",
        recipient_scope="test_scope",
        version=1,
    )

    mock_generate.return_value = IrreversiblePseudonym(
        value="test_pseudonym_value",
        version=1,
        older=(),
    )

    response = client.post(
        "/exchange/irreversible-pseudonym",
        json=request_body,
        headers=valid_irreversible_pseudonym_headers,
    )

    assert response.status_code == 201
    assert response.headers["content-type"] == "application/jwe"
    assert response.content


def test_post_irreversible_pseudonym_should_return_400_when_invalid_personal_id(
    client: TestClient,
    org_with_irreversible_pseudonym_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    valid_irreversible_pseudonym_headers: dict[str, str],
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_irreversible_pseudonym_type,
        domains=["test_scope"],
    )

    request_body = {
        "personalId": "invalid_personal_id",  # Invalid format
        "recipientOrganization": f"oin:{org_with_irreversible_pseudonym_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    response = client.post(
        "/exchange/irreversible-pseudonym",
        json=request_body,
        headers=valid_irreversible_pseudonym_headers,
    )

    assert response.status_code == 400


def test_post_irreversible_pseudonym_should_return_403_when_missing_scope(
    client: TestClient,
    org_with_irreversible_pseudonym_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    valid_irreversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_irreversible_pseudonym_type,
        domains=["test_scope"],
    )

    # Create headers WITHOUT the required scope
    headers = {**valid_irreversible_pseudonym_headers}
    del headers["x-gf-scope"]  # Remove the scope

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org_with_irreversible_pseudonym_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    response = client.post(
        "/exchange/irreversible-pseudonym",
        json=request_body,
        headers=headers,
    )

    assert response.status_code == 403


def test_post_irreversible_pseudonym_should_return_404_when_no_public_key_for_scope(
    client: TestClient,
    org_with_irreversible_pseudonym_type: OrganizationEntity,
    valid_irreversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
) -> None:
    # Don't set up a public key for the scope - this should trigger 404
    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org_with_irreversible_pseudonym_type.external_id.value}",
        "recipientScope": "non_existent_scope",
    }

    response = client.post(
        "/exchange/irreversible-pseudonym",
        json=request_body,
        headers=valid_irreversible_pseudonym_headers,
    )

    assert response.status_code == 404


@patch("app.services.irreversible.service.IrreversiblePseudonymService.generate")
@patch("app.services.reversible.service.ReversiblePseudonymService.reverse")
def test_post_irreversible_pseudonym_should_return_410_when_key_version_destroyed(
    mock_reverse: MagicMock,
    mock_generate: MagicMock,
    client: TestClient,
    org_with_irreversible_pseudonym_type: OrganizationEntity,
    valid_irreversible_pseudonym_headers: dict[str, str],
) -> None:
    reversible_pseudonym = "pseudonym:reversible:dGVzdA=="

    request_body = {
        "reversiblePseudonym": reversible_pseudonym,
        "recipientOrganization": f"oin:{org_with_irreversible_pseudonym_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    # Mock reverse to raise VERSION_DESTROYED
    mock_reverse.side_effect = PseudonymVersionDestroyedError()

    response = client.post(
        "/exchange/irreversible-pseudonym",
        json=request_body,
        headers=valid_irreversible_pseudonym_headers,
    )

    assert response.status_code == 410


@patch("app.services.irreversible.service.IrreversiblePseudonymService.generate")
def test_post_irreversible_pseudonym_should_return_500_when_crypto_failure(
    mock_generate: MagicMock,
    client: TestClient,
    org_with_irreversible_pseudonym_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    mock_personal_id: PersonalId,
    valid_irreversible_pseudonym_headers: dict[str, str],
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_irreversible_pseudonym_type,
        domains=["test_scope"],
    )

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org_with_irreversible_pseudonym_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    # Mock generate to raise CRYPTO_FAILURE
    mock_generate.side_effect = CryptoFailureError()

    response = client.post(
        "/exchange/irreversible-pseudonym",
        json=request_body,
        headers=valid_irreversible_pseudonym_headers,
    )

    assert response.status_code == 500


@patch("app.services.irreversible.service.IrreversiblePseudonymService.generate")
def test_post_irreversible_pseudonym_should_return_503_when_hsm_unreachable(
    mock_generate: MagicMock,
    client: TestClient,
    org_with_irreversible_pseudonym_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    mock_personal_id: PersonalId,
    valid_irreversible_pseudonym_headers: dict[str, str],
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=org_with_irreversible_pseudonym_type,
        domains=["test_scope"],
    )

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org_with_irreversible_pseudonym_type.external_id.value}",
        "recipientScope": "test_scope",
    }

    # Mock generate to raise HSM_UNREACHABLE
    mock_generate.side_effect = HsmUnreachableError()

    response = client.post(
        "/exchange/irreversible-pseudonym",
        json=request_body,
        headers=valid_irreversible_pseudonym_headers,
    )

    assert response.status_code == 503
