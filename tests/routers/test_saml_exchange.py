from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from app.db.models.organization import OrganizationEntity
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin


@pytest.fixture()
def valid_saml_headers(
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
        "x-gf-scope": AuthorizationScope.SAML_PSEUDONYM.value,
    }


@patch("app.services.saml.client.SamlServiceClient.decrypt")
def test_post_reversible_pseudonym_should_return_200(
    mock_decrypt: MagicMock,
    client: TestClient,
    org_with_personal_id_type: OrganizationEntity,
    valid_saml_headers: dict[str, str],
) -> None:
    # Mock the SAML client to return a successful response
    mock_decrypt.return_value = {"decrypted": "saml_response"}

    payload = {"saml_response": "encrypted_data"}

    response = client.post(
        "/saml-exchange/reversible-pseudonym",
        json=payload,
        headers=valid_saml_headers,
    )

    assert response.status_code == 200
    assert response.json() == {"decrypted": "saml_response"}


@patch("app.services.saml.client.SamlServiceClient.decrypt")
def test_post_reversible_pseudonym_should_return_502_when_saml_error(
    mock_decrypt: MagicMock,
    client: TestClient,
    org_with_personal_id_type: OrganizationEntity,
    valid_saml_headers: dict[str, str],
) -> None:
    from app.services.saml.client import SamlServiceError

    # Mock the SAML client to raise an error
    mock_decrypt.side_effect = SamlServiceError("saml_service_error", "Service error")

    payload = {"saml_response": "encrypted_data"}

    response = client.post(
        "/saml-exchange/reversible-pseudonym",
        json=payload,
        headers=valid_saml_headers,
    )

    assert response.status_code == 502
