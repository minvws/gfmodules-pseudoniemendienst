from collections.abc import Callable
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.exceptions.pseudonym import (
    HsmOperationFailedError,
    HsmTimeoutError,
    HsmUnreachableError,
)
from app.models.auth.data import AuthorizationScope
from app.services.organization_public_key_service import OrganizationPublicKeyService
from tests.conftest import blinded_input, setup_org_and_key


def test_post_eval_should_return_jwe(
    client: TestClient,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
    headers_with_scopes: Callable[..., dict[str, str]],
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:

    # Set up recipient organization with a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=persisted_organization,
        domains=["test_scope"],
    )

    # Create auth headers with the required scope
    headers = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)

    request_body = {
        "encryptedPersonalId": blinded_input(),
        "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
        "recipientScope": "test_scope",
    }

    # Mock the OPRF evaluation to return a valid result
    with patch("app.services.oprf.oprf_service.OprfService.eval_blind") as mock_eval:
        # Create a mock result
        mock_result = MagicMock()
        mock_result.jwe = "fake.jwe.token"
        mock_result.key_versions = [1]
        mock_eval.return_value = mock_result

        response = client.post("/oprf/eval", json=request_body, headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert "jwe" in data
        assert data["jwe"] == "fake.jwe.token"


def test_post_eval_should_return_403_when_unauthorized(
    client: TestClient,
) -> None:
    request_body = {
        "encryptedPersonalId": blinded_input(),
        "recipientOrganization": "oin:00000099000000001000",
        "recipientScope": "test_scope",
    }

    response = client.post("/oprf/eval", json=request_body)

    assert response.status_code == 403


def test_post_eval_should_return_422_when_missing_required_field(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
) -> None:
    # Missing recipientOrganization and recipientScope
    request_body = {
        "encryptedPersonalId": blinded_input(),
    }

    headers = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)

    response = client.post("/oprf/eval", json=request_body, headers=headers)

    assert response.status_code == 422


def test_post_eval_should_return_400_when_invalid_base64(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    persisted_organization: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    # Set up a public key for the scope so we pass the 404 check
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=persisted_organization,
        domains=["test_scope"],
    )

    request_body = {
        "encryptedPersonalId": "!!!",
        "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
        "recipientScope": "test_scope",
    }

    headers = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)

    response = client.post("/oprf/eval", json=request_body, headers=headers)

    assert response.status_code == 400


def test_post_eval_should_return_404_when_no_public_key_for_scope(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    persisted_organization: OrganizationEntity,
) -> None:
    # Don't set up a public key for the scope - this should trigger 404
    request_body = {
        "encryptedPersonalId": blinded_input(),
        "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
        "recipientScope": "non_existent_scope",
    }

    headers = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)

    response = client.post("/oprf/eval", json=request_body, headers=headers)

    assert response.status_code == 404


def test_post_eval_should_return_502_when_hsm_refused(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    persisted_organization: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=persisted_organization,
        domains=["test_scope"],
    )

    request_body = {
        "encryptedPersonalId": blinded_input(),
        "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
        "recipientScope": "test_scope",
    }

    headers = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)

    # Mock eval_blind to raise HSM_OPERATION_FAILED
    with patch("app.services.oprf.oprf_service.OprfService.eval_blind") as mock_eval:
        mock_eval.side_effect = HsmOperationFailedError()

        response = client.post("/oprf/eval", json=request_body, headers=headers)

        assert response.status_code == 502


def test_post_eval_should_return_503_when_hsm_unreachable(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    persisted_organization: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=persisted_organization,
        domains=["test_scope"],
    )

    request_body = {
        "encryptedPersonalId": blinded_input(),
        "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
        "recipientScope": "test_scope",
    }

    headers = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)

    # Mock eval_blind to raise HSM_UNREACHABLE
    with patch("app.services.oprf.oprf_service.OprfService.eval_blind") as mock_eval:
        mock_eval.side_effect = HsmUnreachableError()

        response = client.post("/oprf/eval", json=request_body, headers=headers)

        assert response.status_code == 503


def test_post_eval_should_return_504_when_hsm_timeout(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    persisted_organization: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    # Set up a public key for the scope
    setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=persisted_organization,
        domains=["test_scope"],
    )

    request_body = {
        "encryptedPersonalId": blinded_input(),
        "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
        "recipientScope": "test_scope",
    }

    headers = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)

    # Mock eval_blind to raise HSM_TIMEOUT
    with patch("app.services.oprf.oprf_service.OprfService.eval_blind") as mock_eval:
        mock_eval.side_effect = HsmTimeoutError()

        response = client.post("/oprf/eval", json=request_body, headers=headers)

        assert response.status_code == 504
