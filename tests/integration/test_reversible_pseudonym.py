"""Integration tests for the reversible pseudonym exchange endpoint.

These tests verify the full flow from HTTP request to encrypted response,
including authorization, pseudonym generation, JWE encryption, and audit logging.
"""

import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi import FastAPI
from sqlalchemy import select
from starlette.testclient import TestClient

from app.container import (
    get_auth_headers_service,
    get_hsm_key_version_service,
    get_jwt_signing_service,
    get_organization_public_key_service,
    get_reversible_pseudonym_service,
)
from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.models.organization import OrganizationEntity
from app.db.models.personal_id_type import PersonalIdTypeEntity
from app.db.session import DbSession
from app.enums.personal_id_type import PersonalIdType
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.routers.errors import (
    install_app_error_handler,
    install_validation_error_handler,
)
from app.routers.exchange.router import router as exchange_router
from app.routers.health import router as health_router
from app.services.auth.header import AuthHeaderService
from app.services.authorization_service import AuthorizationService
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.jwt_signer import JwtSigningService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversiblePseudonymService
from tests.conftest import ALL_SCOPES, JWT_ISSUER, decrypt_signed, setup_org_and_key

# Constants
TEST_SCOPE = "test_scope"
ENDPOINT = "/exchange/reversible-pseudonym"
LOGGER_NAME = "app.routers.exchange.reversible_pseudonym"


# ==================== APP SETUP ====================


@pytest.fixture
def reversible_pseudonym_app(
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    hsm_key_version_service: HsmKeyVersionService,
    organization_public_key_service: OrganizationPublicKeyService,
    authorization_service: AuthorizationService,
    auth_headers_service: AuthHeaderService,
    jwt_signing_service: JwtSigningService,
) -> FastAPI:
    """Minimal FastAPI app for reversible pseudonym tests, using local key operations."""
    from app.container import get_jwe_token_service
    from app.services.jwe_token import JweTokenService

    app = FastAPI()

    # Include only necessary routers
    app.include_router(health_router)
    app.include_router(exchange_router)

    # Install error handlers
    install_validation_error_handler(app)
    install_app_error_handler(app)

    # Create JWE token service
    jwe_token_service = JweTokenService(jwt_signing_service)

    # Override dependencies to use local services
    app.dependency_overrides[get_reversible_pseudonym_service] = lambda: (
        local_reversible_pseudonym_service
    )
    app.dependency_overrides[get_hsm_key_version_service] = lambda: (
        hsm_key_version_service
    )
    app.dependency_overrides[get_organization_public_key_service] = lambda: (
        organization_public_key_service
    )
    app.dependency_overrides[get_auth_headers_service] = lambda: auth_headers_service
    app.dependency_overrides[get_jwt_signing_service] = lambda: jwt_signing_service
    app.dependency_overrides[get_jwe_token_service] = lambda: jwe_token_service

    return app


# @pytest.fixture
# def client(reversible_pseudonym_app: FastAPI) -> TestClient:
#     """TestClient for the reversible pseudonym app."""
#     return TestClient(reversible_pseudonym_app)
#

# ==================== FIXTURES ====================


@pytest.fixture
def reversible_pseudonym_sender_org(
    valid_organization_id: Oin,
    db_session: DbSession,
) -> OrganizationEntity:
    """Sender organization with REVERSIBLE_PSEUDONYM request type and key versions.

    This org is authorized to request reversible pseudonyms.
    """
    # Check if organization already exists
    org = (
        db_session.session.query(OrganizationEntity)
        .filter(OrganizationEntity.external_id == valid_organization_id.value)
        .first()
    )

    if org:
        return org

    # Get the personal ID type
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.REVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )

    # Create organization with REVERSIBLE_PSEUDONYM type and key versions
    org = OrganizationEntity(
        external_id=valid_organization_id,
        name="reversible pseudonym sender org",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=list(personal_ids),
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
    )
    db_session.add(org)
    db_session.commit()
    return org


@pytest.fixture
def reversible_pseudonym_recipient_org(
    org_with_reversible_pseudonym_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
    db_session: DbSession,
) -> tuple[OrganizationEntity, str]:
    """Recipient organization with a public key for TEST_SCOPE and active key versions.

    Returns:
        tuple[OrganizationEntity, str]: (recipient org, private key PEM)
    """
    # Ensure the org has active key versions
    if not org_with_reversible_pseudonym_type.hsm_key_versions:
        org_with_reversible_pseudonym_type.hsm_key_versions.append(
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        )
        db_session.commit()

    priv_key = setup_org_and_key(
        organization_public_key_service,
        org_with_reversible_pseudonym_type,
        [TEST_SCOPE],
    )
    return org_with_reversible_pseudonym_type, priv_key


@pytest.fixture
def reversible_pseudonym_headers(
    reversible_pseudonym_sender_org: OrganizationEntity,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    expected_audiences: list[str],
) -> dict[str, str]:
    """Headers for a sender authorized to request reversible pseudonyms.

    Uses:
        - x-gf-sub: sender org OIN
        - x-gf-act-sub: client org OIN
        - x-gf-act-cn: client common name
        - x-gf-audience: first expected audience
        - x-gf-scope: ALL_SCOPES
    """
    return {
        "x-gf-sub": reversible_pseudonym_sender_org.external_id.value,
        "x-gf-act-sub": valid_client_organization_id.value,
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": expected_audiences[0],
        "x-gf-scope": ALL_SCOPES,
    }


@pytest.fixture
def reversible_pseudonym_request_body(
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    mock_personal_id: PersonalId,
) -> dict[str, Any]:
    """Valid request body for reversible pseudonym exchange."""
    org, _ = reversible_pseudonym_recipient_org
    return {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }


@pytest.fixture
def reversible_pseudonym_recipient_org_for_scope_test(
    db_session: DbSession,
    organization_public_key_service: OrganizationPublicKeyService,
) -> tuple[OrganizationEntity, str]:
    """Recipient organization with public keys for scope_a and scope_b."""
    from app.db.models.personal_id_type import PersonalIdTypeEntity
    from app.enums.personal_id_type import PersonalIdType

    # Get the personal ID type
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.REVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )

    # Create a new organization
    org = OrganizationEntity(
        external_id=Oin("00000099000000009000"),  # New OIN
        name="reversible pseudonym recipient org for scope test",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=[],
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
    )
    db_session.add(org)
    db_session.commit()

    # Set up public keys for scope_a and scope_b
    priv_key = setup_org_and_key(
        organization_public_key_service,
        org,
        ["scope_a", "scope_b"],
    )
    return org, priv_key


# ==================== TESTS ====================


def test_happy_path_returns_jwe_with_reversible_pseudonym(
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_request_body: dict[str, Any],
    reversible_pseudonym_headers: dict[str, str],
    jwt_signing_service: JwtSigningService,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests the full happy path: request → JWE response with reversible pseudonym.

    Verifies:
    - Response status code is 201
    - Response content type is application/jwe
    - JWE/JWS claims contain the reversible pseudonym
    - Audit logging records the PSEUDONYM_REVERSIBLE_CREATED event (220400)
    """
    # Attach the handler BEFORE making the request
    records = record_logs(LOGGER_NAME)

    org, priv_key = reversible_pseudonym_recipient_org

    response = client.post(
        ENDPOINT,
        json=reversible_pseudonym_request_body,
        headers=reversible_pseudonym_headers,
    )

    # Verify response status and headers
    assert response.status_code == 201
    assert response.headers["content-type"] == "application/jwe"

    # Decrypt and verify JWE/JWS
    _, _, claims = decrypt_signed(response.text, priv_key, jwt_signing_service)

    # Verify claims
    assert claims["subject"].startswith("pseudonym:reversible:")
    assert claims["aud"] == f"oin:{org.external_id.value}"
    assert claims["scope"] == TEST_SCOPE
    assert claims["keyVersion"] == 1
    assert "extraVersions" not in claims

    # Verify audit logging by event_id (220400 = PSEUDONYM_REVERSIBLE_CREATED)
    created_events = [r for r in records if getattr(r, "event_id", None) == "220400"]
    assert len(created_events) == 1


def test_with_jwt_signing_returns_signed_reversible_pseudonym(
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_request_body: dict[str, Any],
    reversible_pseudonym_headers: dict[str, str],
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that the response includes a signed JWS when JWT signing is enabled."""
    org, priv_key = reversible_pseudonym_recipient_org

    response = client.post(
        ENDPOINT,
        json=reversible_pseudonym_request_body,
        headers=reversible_pseudonym_headers,
    )

    assert response.status_code == 201
    assert response.headers["content-type"] == "application/jwe"

    # Decrypt and verify JWE/JWS
    jwe_headers, jws_headers, claims = decrypt_signed(
        response.text, priv_key, jwt_signing_service
    )

    # Verify JWE headers
    assert jwe_headers["alg"] == "RSA-OAEP"
    assert jwe_headers["enc"] == "A256GCM"

    # Verify JWS headers
    assert jws_headers["alg"] == "PS256"
    assert jws_headers["kid"] == jwt_signing_service.active.kid
    assert jws_headers["typ"] == "JWT"

    # Verify claims
    assert claims["iss"] == JWT_ISSUER
    assert claims["subject"].startswith("pseudonym:reversible:")
    assert claims["aud"] == f"oin:{org.external_id.value}"


def test_pseudonym_is_deterministic_and_accepts_both_personal_id_forms(
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that the same input produces the same pseudonym, and both string and dict personal ID formats work."""
    org, priv_key = reversible_pseudonym_recipient_org

    # Test with string-format personal ID (using mock_personal_id.as_str())
    string_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Test with dict-format personal ID (using mock_personal_id.as_dict())
    dict_body = {
        "personalId": mock_personal_id.as_dict(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Make both requests
    string_response = client.post(
        ENDPOINT,
        json=string_body,
        headers=reversible_pseudonym_headers,
    )
    dict_response = client.post(
        ENDPOINT,
        json=dict_body,
        headers=reversible_pseudonym_headers,
    )

    # Both should succeed
    assert string_response.status_code == 201
    assert dict_response.status_code == 201

    # Decrypt both responses
    _, _, string_claims = decrypt_signed(
        string_response.text, priv_key, jwt_signing_service
    )
    _, _, dict_claims = decrypt_signed(
        dict_response.text, priv_key, jwt_signing_service
    )

    # The pseudonyms should be identical
    assert string_claims["subject"] == dict_claims["subject"]


def test_scope_changes_the_pseudonym(
    client: TestClient,
    reversible_pseudonym_recipient_org_for_scope_test: tuple[OrganizationEntity, str],
    reversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that changing the scope changes the pseudonym."""
    org, priv_key = reversible_pseudonym_recipient_org_for_scope_test

    # Request with scope "scope_a"
    body_one = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": "scope_a",
    }

    # Request with scope "scope_b"
    body_other = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": "scope_b",
    }

    # Make both requests
    response_one = client.post(
        ENDPOINT,
        json=body_one,
        headers=reversible_pseudonym_headers,
    )
    response_other = client.post(
        ENDPOINT,
        json=body_other,
        headers=reversible_pseudonym_headers,
    )

    # Both should succeed
    assert response_one.status_code == 201
    assert response_other.status_code == 201

    # Decrypt both responses
    _, _, claims_one = decrypt_signed(response_one.text, priv_key, jwt_signing_service)
    _, _, claims_other = decrypt_signed(
        response_other.text, priv_key, jwt_signing_service
    )

    # The pseudonyms should be different
    assert claims_one["subject"] != claims_other["subject"]


def test_pseudonym_differs_per_personal_id(
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
    mock_personal_id_2: PersonalId,
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that different personal IDs produce different reversible pseudonyms."""
    org, priv_key = reversible_pseudonym_recipient_org

    # Request with first personal ID
    first_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Request with second personal ID
    second_body = {
        "personalId": mock_personal_id_2.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Make both requests
    first_response = client.post(
        ENDPOINT,
        json=first_body,
        headers=reversible_pseudonym_headers,
    )
    second_response = client.post(
        ENDPOINT,
        json=second_body,
        headers=reversible_pseudonym_headers,
    )

    # Both should succeed
    assert first_response.status_code == 201
    assert second_response.status_code == 201

    # Decrypt both responses
    _, _, first_claims = decrypt_signed(
        first_response.text, priv_key, jwt_signing_service
    )
    _, _, second_claims = decrypt_signed(
        second_response.text, priv_key, jwt_signing_service
    )

    # The pseudonyms should be different
    assert first_claims["subject"] != second_claims["subject"]


@pytest.mark.parametrize(
    "as_input",
    [
        lambda value: {"reversiblePseudonym": value},
        lambda value: {"reversiblePseudonym": f"pseudonym:reversible:{value}"},
    ],
    ids=["bare", "as-received"],
)
def test_reversible_pseudonym_of_the_caller_is_accepted_as_input(
    as_input: Callable[[str], dict[str, str]],
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_headers: dict[str, str],
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    jwt_signing_service: JwtSigningService,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a reversible pseudonym from the caller's own organization is accepted as input."""
    # Get the sender org OIN from the headers
    sender_oin = Oin(reversible_pseudonym_headers["x-gf-sub"])
    records = record_logs(LOGGER_NAME)

    # Generate a reversible pseudonym for the sender org
    reversible_pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        sender_oin,
        "own-scope",  # Any scope, since it's for the sender
    )

    # Request with the reversible pseudonym (bare or prefixed)
    request_body = {
        **as_input(reversible_pseudonym.value),
        "recipientOrganization": f"oin:{reversible_pseudonym_recipient_org[0].external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Request with the personal ID directly
    personal_id_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{reversible_pseudonym_recipient_org[0].external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Make both requests
    from_personal_id = client.post(
        ENDPOINT,
        json=personal_id_body,
        headers=reversible_pseudonym_headers,
    )
    from_pseudonym = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Both should succeed
    assert from_personal_id.status_code == 201
    assert from_pseudonym.status_code == 201

    # Decrypt both responses
    _, _, from_personal_id_claims = decrypt_signed(
        from_personal_id.text,
        reversible_pseudonym_recipient_org[1],
        jwt_signing_service,
    )
    _, _, from_pseudonym_claims = decrypt_signed(
        from_pseudonym.text,
        reversible_pseudonym_recipient_org[1],
        jwt_signing_service,
    )

    # The pseudonyms should be identical
    assert from_personal_id_claims["subject"] == from_pseudonym_claims["subject"]

    # Verify audit logging (2 events for PSEUDONYM_REVERSIBLE_CREATED)
    created_events = [r for r in records if getattr(r, "event_id", None) == "220400"]
    assert len(created_events) == 2


def test_reversible_pseudonym_of_another_organization_is_refused(
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_headers: dict[str, str],
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a reversible pseudonym from another organization is refused."""
    # Get the recipient org OIN from the fixture
    recipient_oin = reversible_pseudonym_recipient_org[0].external_id
    records = record_logs(LOGGER_NAME)

    # Generate a reversible pseudonym for the RECIPIENT org (not the sender)
    reversible_pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        recipient_oin,
        TEST_SCOPE,
    )

    request_body = {
        "reversiblePseudonym": reversible_pseudonym.value,
        "recipientOrganization": f"oin:{recipient_oin.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Should return 400
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}

    # Verify audit logging (PSEUDONYM_CREATE_FAILED with event_id 220403)
    failed_events = [r for r in records if getattr(r, "event_id", None) == "220403"]
    assert len(failed_events) == 1
    assert failed_events[0].error_type == "invalid_pseudonym"  # type: ignore


def test_reversible_pseudonym_with_destroyed_key_version_is_gone(
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_headers: dict[str, str],
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    hsm_key_version_service: HsmKeyVersionService,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a reversible pseudonym with a destroyed key version is gone (410)."""
    # Get the sender org OIN from the headers
    sender_oin = Oin(reversible_pseudonym_headers["x-gf-sub"])
    records = record_logs(LOGGER_NAME)

    # Generate a reversible pseudonym for the sender org
    reversible_pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        sender_oin,
        "own-scope",
    )

    request_body = {
        "reversiblePseudonym": reversible_pseudonym.value,
        "recipientOrganization": f"oin:{reversible_pseudonym_recipient_org[0].external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Destroy all key versions for the sender org
    for version in hsm_key_version_service.get_versions_by_organization_id(sender_oin):
        hsm_key_version_service.mark_removed(version.id)

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Should return 410
    assert response.status_code == 410
    assert response.json() == {"detail": "Pseudonym key version no longer available"}

    # Verify audit logging (PSEUDONYM_CREATE_FAILED with event_id 220403)
    failed_events = [r for r in records if getattr(r, "event_id", None) == "220403"]
    assert len(failed_events) == 1
    assert failed_events[0].error_type == "version_destroyed"  # type: ignore


@pytest.mark.parametrize(
    "fields",
    [{}, {"personalId": "NL:bsn:999990020", "reversiblePseudonym": "AQAB"}],
    ids=["neither", "both"],
)
def test_not_exactly_one_input_is_rejected_without_echoing_it(
    fields: dict[str, str],
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_headers: dict[str, str],
) -> None:
    """Tests that exactly one of personalId or reversiblePseudonym is required."""
    org, _ = reversible_pseudonym_recipient_org

    request_body = {
        **fields,
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Should return 422 (Unprocessable Entity)
    assert response.status_code == 422

    # Verify the input is NOT echoed in the response
    assert "NL:bsn:999990020" not in response.text
    assert "AQAB" not in response.text


@pytest.mark.parametrize(
    "personal_id,kind",
    [
        ("999990020", "formaat"),  # Missing landCode and type
        ("NL:passport:999990020", "formaat"),  # Wrong ID type
        ("N:bsn:999990020", "formaat"),  # Wrong landCode
        ({"landCode": "NL", "value": "999990020"}, "formaat"),  # Missing type
        ("NL:bsn:999990020a", "formaat"),  # Invalid characters
        ("NL:bsn:99999002", "lengte"),  # Wrong length
        ("NL:bsn:950000013", "elfproef"),  # Fails elfproef
        (
            {"landCode": "NL", "type": "bsn", "value": "123456789"},
            "elfproef",
        ),  # Fails elfproef
        ("pseudonym:reversible:AQAB", "formaat"),  # Not a personal ID
    ],
    ids=[
        "missing_landcode_and_type",
        "wrong_id_type",
        "wrong_landcode",
        "missing_type",
        "invalid_chars",
        "wrong_length",
        "elfproef_failure",
        "elfproef_failure_dict",
        "not_personal_id",
    ],
)
def test_malformed_personal_id_is_rejected_and_audited_without_the_value(
    personal_id: str | dict[str, str],
    kind: str,
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_headers: dict[str, str],
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that malformed personal IDs are rejected and the value is not logged."""
    org, _ = reversible_pseudonym_recipient_org
    records = record_logs(LOGGER_NAME)

    request_body = {
        "personalId": personal_id,
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Should return 400
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid personal ID"}

    # Verify audit logging (PERSONAL_ID_VALIDATION_FAILED with event_id 220404)
    failed_events = [r for r in records if getattr(r, "event_id", None) == "220404"]
    assert len(failed_events) == 1
    assert failed_events[0].validation_error == kind  # type: ignore

    # Verify the personal ID value is NOT in any log record
    personal_id_value = (
        personal_id["value"]
        if isinstance(personal_id, dict)
        else personal_id.split(":")[-1]
    )
    for record in records:
        assert personal_id_value not in str(record.msg)


def test_personal_id_value_never_appears_in_logs_on_success(
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_request_body: dict[str, Any],
    reversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that the personal ID value never appears in logs on success."""
    records = record_logs(LOGGER_NAME)

    response = client.post(
        ENDPOINT,
        json=reversible_pseudonym_request_body,
        headers=reversible_pseudonym_headers,
    )

    assert response.status_code == 201
    # Extract the BSN value from the personal ID (e.g., "NL:bsn:950000012" → "950000012")
    bsn_value = mock_personal_id.id_number()
    for record in records:
        assert bsn_value not in str(record.msg)


def test_requires_the_pseudonym_scope(
    client: TestClient,
    reversible_pseudonym_sender_org: OrganizationEntity,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    expected_audiences: list[str],
    mock_personal_id: PersonalId,
) -> None:
    """Tests that the prs:pseudonym scope is required to request reversible pseudonyms."""
    org, _ = reversible_pseudonym_recipient_org

    # Helper to build headers with custom scopes
    def build_headers(scopes: list[AuthorizationScope]) -> dict[str, str]:
        return {
            "x-gf-sub": reversible_pseudonym_sender_org.external_id.value,
            "x-gf-act-sub": valid_client_organization_id.value,
            "x-gf-act-cn": valid_client_common_name,
            "x-gf-audience": expected_audiences[0],
            "x-gf-scope": " ".join(scope.value for scope in scopes),
        }

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Test without the pseudonym scope (only OPRF_PSEUDONYM)
    without_pseudonym_scope = build_headers([AuthorizationScope.OPRF_PSEUDONYM])
    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=without_pseudonym_scope,
    )

    # Should return 403
    assert response.status_code == 403

    # Test with the pseudonym scope (should succeed)
    with_pseudonym_scope = build_headers([AuthorizationScope.PSEUDONYM])
    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=with_pseudonym_scope,
    )

    # Should return 201
    assert response.status_code == 201


def test_unregistered_caller_is_rejected(
    client: TestClient,
    reversible_pseudonym_headers: dict[str, str],
    org_with_reversible_pseudonym_type: OrganizationEntity,
    mock_personal_id: PersonalId,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    """Tests that an unregistered caller is rejected."""
    # Set up a public key for the recipient org to avoid 404
    setup_org_and_key(
        organization_public_key_service,
        org_with_reversible_pseudonym_type,
        [TEST_SCOPE],
    )

    # Use headers with an unregistered sender (x-gf-sub)
    headers = {
        **reversible_pseudonym_headers,
        "x-gf-sub": "00000099000000009000",  # Valid but unregistered OIN
    }

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org_with_reversible_pseudonym_type.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Organization does not exist"}


@pytest.mark.parametrize(
    "value",
    ["not-a-pseudonym", "pseudonym:irreversible:AQAB"],
    ids=["garbage", "irreversible-subject"],
)
def test_garbage_reversible_pseudonym_is_refused(
    value: str,
    client: TestClient,
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    reversible_pseudonym_headers: dict[str, str],
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that garbage reversible pseudonyms are refused with a 400 error."""
    records = record_logs(LOGGER_NAME)

    request_body = {
        "reversiblePseudonym": value,
        "recipientOrganization": f"oin:{reversible_pseudonym_recipient_org[0].external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}

    # Verify audit logging (PSEUDONYM_CREATE_FAILED with event_id 220403)
    failed_events = [r for r in records if getattr(r, "event_id", None) == "220403"]
    assert len(failed_events) == 1


def test_sender_not_allowed_to_request_is_refused_before_anything_else(
    client: TestClient,
    reversible_pseudonym_headers: dict[str, str],
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    db_session: DbSession,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a sender not allowed to request is refused before any processing."""
    # Create a sender org that is NOT allowed to request REVERSIBLE_PSEUDONYM
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.IRREVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    unauthorized_sender = OrganizationEntity(
        external_id=Oin("00000099000000004000"),  # New OIN
        name="unauthorized sender org",
        receive_personal_id_types=[],
        request_personal_id_types=list(personal_ids),  # Only irreversible
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
    )
    db_session.add(unauthorized_sender)
    db_session.commit()

    # Use the unauthorized sender in the headers
    headers = {
        **reversible_pseudonym_headers,
        "x-gf-sub": unauthorized_sender.external_id.value,  # Override sender
    }

    # Attach the handler BEFORE making the request
    records = record_logs(LOGGER_NAME)

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{reversible_pseudonym_recipient_org[0].external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=headers,
    )

    # Should return 403
    assert response.status_code == 403
    assert "Not allowed to request" in response.json()["detail"]

    # Verify audit logging (AUTHORIZATION_DENIED with event_id 200402)
    denied_events = [r for r in records if getattr(r, "event_id", None) == "200402"]
    assert len(denied_events) == 1


def test_sender_permission_is_read_from_the_verified_caller_not_the_acting_org(
    client: TestClient,
    reversible_pseudonym_headers: dict[str, str],
    reversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    db_session: DbSession,
    mock_personal_id: PersonalId,
) -> None:
    """Tests that sender permission is read from the verified caller, not the acting org."""
    # Create a sender org that is NOT allowed to request REVERSIBLE_PSEUDONYM
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.IRREVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    unauthorized_sender = OrganizationEntity(
        external_id=Oin("00000099000000004000"),  # New OIN
        name="unauthorized sender org",
        receive_personal_id_types=[],
        request_personal_id_types=list(personal_ids),  # Only irreversible
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
    )
    db_session.add(unauthorized_sender)
    db_session.commit()

    # Create an acting org that IS allowed to request REVERSIBLE_PSEUDONYM
    authorized_acting = OrganizationEntity(
        external_id=Oin("00000099000000005000"),  # New OIN
        name="authorized acting org",
        receive_personal_id_types=[],
        request_personal_id_types=list(
            personal_ids
        ),  # Only irreversible (but this shouldn't matter)
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
    )
    db_session.add(authorized_acting)
    db_session.commit()

    # Use the unauthorized sender in x-gf-sub and authorized acting in x-gf-act-sub
    headers = {
        **reversible_pseudonym_headers,
        "x-gf-sub": unauthorized_sender.external_id.value,  # Unauthorized sender
        # Authorized acting (but should not matter)
        "x-gf-act-sub": authorized_acting.external_id.value,
    }

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{reversible_pseudonym_recipient_org[0].external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=headers,
    )

    # Should return 403 (because the sender is not allowed, even though the acting org is)
    assert response.status_code == 403


def test_recipient_not_allowed_to_receive_is_refused(
    client: TestClient,
    reversible_pseudonym_headers: dict[str, str],
    db_session: DbSession,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a recipient org not allowed to receive reversible pseudonyms is refused."""
    # Create a recipient org that is NOT allowed to receive REVERSIBLE_PSEUDONYM
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.IRREVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    unauthorized_recipient = OrganizationEntity(
        external_id=Oin("00000099000000005000"),  # New OIN
        name="unauthorized recipient org",
        receive_personal_id_types=list(personal_ids),  # Only irreversible
        request_personal_id_types=[],
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
    )
    db_session.add(unauthorized_recipient)
    db_session.commit()

    # Attach the handler BEFORE making the request
    records = record_logs(LOGGER_NAME)

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{unauthorized_recipient.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Should return 404
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }

    # Verify audit logging (AUTHORIZATION_DENIED with event_id 200402)
    denied_events = [r for r in records if getattr(r, "event_id", None) == "200402"]
    assert len(denied_events) == 1


def test_unknown_recipient_is_not_found(
    client: TestClient,
    reversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
    valid_organization_id_2: Oin,
) -> None:
    """Tests that an unknown recipient is not found."""
    # Use valid_organization_id_2 as the recipient (not registered in the test database)
    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{valid_organization_id_2.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Should return 404
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }


def test_recipient_permission_is_read_from_the_recipient_organization(
    client: TestClient,
    reversible_pseudonym_headers: dict[str, str],
    db_session: DbSession,
    mock_personal_id: PersonalId,
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    """Tests that recipient permission is read from the recipient organization."""
    # Create a recipient org that IS allowed to receive REVERSIBLE_PSEUDONYM
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.REVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    authorized_recipient = OrganizationEntity(
        external_id=Oin("00000099000000006000"),  # New OIN
        name="authorized recipient org",
        receive_personal_id_types=list(personal_ids),  # Allowed to receive
        request_personal_id_types=[],
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
    )
    db_session.add(authorized_recipient)
    db_session.commit()

    # Set up a public key for the recipient org to avoid 404
    setup_org_and_key(
        organization_public_key_service,
        authorized_recipient,
        [TEST_SCOPE],
    )

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{authorized_recipient.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Should return 201 (success)
    assert response.status_code == 201


def test_recipient_without_public_key_for_scope_is_not_found(
    client: TestClient,
    reversible_pseudonym_headers: dict[str, str],
    db_session: DbSession,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    """Tests that a recipient without a public key for the requested scope is not found."""
    # Create a recipient org that IS allowed to receive REVERSIBLE_PSEUDONYM
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.REVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    recipient_org = OrganizationEntity(
        external_id=Oin("00000099000000008000"),  # New OIN
        name="recipient org without public key for scope",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=[],
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
    )
    db_session.add(recipient_org)
    db_session.commit()

    # Do NOT set up a public key for the recipient org for TEST_SCOPE
    # (This ensures the org has no key for the requested scope)

    # Attach the handler BEFORE making the request
    records = record_logs(LOGGER_NAME)

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{recipient_org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Should return 404
    assert response.status_code == 404
    assert response.json() == {"detail": "Organization domain is not registered"}

    # Verify audit logging (ORGANIZATION_DOMAIN_NOT_REGISTERED with event_id 220407)
    domain_not_registered_events = [
        r for r in records if getattr(r, "event_id", None) == "220407"
    ]
    assert len(domain_not_registered_events) == 1


def test_recipient_without_active_key_version_is_not_found(
    client: TestClient,
    reversible_pseudonym_headers: dict[str, str],
    db_session: DbSession,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    """Tests that a recipient without an active key version is not found."""
    # Create a recipient org that IS allowed to receive REVERSIBLE_PSEUDONYM
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.REVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    recipient_org = OrganizationEntity(
        external_id=Oin("00000099000000009000"),  # New OIN
        name="recipient org without active key version",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=[],
        hsm_key_versions=[],  # No active key versions
    )
    db_session.add(recipient_org)
    db_session.commit()

    # Set up a public key for the recipient org for TEST_SCOPE (but mark it as inactive)
    # This ensures the org has a key for the scope but no active key version
    setup_org_and_key(
        organization_public_key_service,
        recipient_org,
        [TEST_SCOPE],
    )
    # Now, mark all key versions as inactive
    for version in recipient_org.hsm_key_versions:
        # Mark as inactive
        version.to_dt = datetime.now(timezone.utc)  # type: ignore
    db_session.commit()

    # Attach the handler BEFORE making the request
    records = record_logs(LOGGER_NAME)

    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{recipient_org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=reversible_pseudonym_headers,
    )

    # Should return 404
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }

    # Verify audit logging (PSEUDONYM_CREATE_FAILED with event_id 220403)
    failed_events = [r for r in records if getattr(r, "event_id", None) == "220403"]
    assert len(failed_events) == 1
    assert (
        failed_events[0].error_type  # type: ignore
        == "no_active_key_version"
    )
