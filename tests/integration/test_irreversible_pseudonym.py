"""Integration tests for the irreversible pseudonym exchange endpoint.

These tests verify the full flow from HTTP request to encrypted response,
including authorization, pseudonym generation, JWE encryption, and audit logging.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.models.organization import OrganizationEntity
from app.db.models.personal_id_type import PersonalIdTypeEntity
from app.db.session import DbSession
from app.enums.personal_id_type import PersonalIdType
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.jwt_signer import JwtSigningService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversiblePseudonymService
from tests.conftest import ALL_SCOPES, JWT_ISSUER, decrypt_signed, setup_org_and_key

# Constants
TEST_SCOPE = "test_scope"
ENDPOINT = "/exchange/irreversible-pseudonym"
LOGGER_NAME = "app.routers.exchange.irreversible_pseudonym"


@pytest.fixture
def irreversible_pseudonym_sender_org(
    valid_organization_id: Oin,
    db_session: DbSession,
) -> OrganizationEntity:
    """Sender organization with IRREVERSIBLE_PSEUDONYM request type and key versions.

    This org is authorized to request irreversible pseudonyms.
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
                PersonalIdTypeEntity.name == str(PersonalIdType.IRREVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )

    # Create organization with IRREVERSIBLE_PSEUDONYM type and key versions
    org = OrganizationEntity(
        external_id=valid_organization_id,
        name="irreversible pseudonym sender org",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=list(personal_ids),
        hsm_key_versions=[HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))],
    )
    db_session.add(org)
    db_session.commit()
    return org


@pytest.fixture
def irreversible_pseudonym_recipient_org(
    org_with_irreversible_pseudonym_type: OrganizationEntity,
    organization_public_key_service: OrganizationPublicKeyService,
) -> tuple[OrganizationEntity, str]:
    """Recipient organization with a public key for TEST_SCOPE.

    Returns:
        tuple[OrganizationEntity, str]: (recipient org, private key PEM)
    """
    priv_key = setup_org_and_key(
        organization_public_key_service,
        org_with_irreversible_pseudonym_type,
        [TEST_SCOPE],
    )
    return org_with_irreversible_pseudonym_type, priv_key


@pytest.fixture
def irreversible_pseudonym_headers(
    irreversible_pseudonym_sender_org: OrganizationEntity,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    expected_audiences: list[str],
) -> dict[str, str]:
    """Headers for a sender authorized to request irreversible pseudonyms.

    Uses:
        - x-gf-sub: sender org OIN
        - x-gf-act-sub: client org OIN
        - x-gf-act-cn: client common name
        - x-gf-audience: first expected audience
        - x-gf-scope: ALL_SCOPES
    """
    return {
        "x-gf-sub": irreversible_pseudonym_sender_org.external_id.value,
        "x-gf-act-sub": valid_client_organization_id.value,
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": expected_audiences[0],
        "x-gf-scope": ALL_SCOPES,
    }


@pytest.fixture
def irreversible_pseudonym_request_body(
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    mock_personal_id: PersonalId,
) -> dict[str, Any]:
    """Valid request body for irreversible pseudonym exchange.

    Uses:
        - personalId: mock_personal_id (as string)
        - recipientOrganization: recipient org OIN
        - recipientScope: TEST_SCOPE
    """
    org, _ = irreversible_pseudonym_recipient_org
    return {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }


# ==================== TESTS ====================


def test_happy_path_returns_jwe_with_irreversible_pseudonym(
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_request_body: dict[str, Any],
    irreversible_pseudonym_headers: dict[str, str],
    jwt_signing_service: JwtSigningService,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests the full happy path: request → JWE response with irreversible pseudonym.

    Verifies:
    - Response status code is 201
    - Response content type is application/jwe
    - JWE/JWS claims contain the irreversible pseudonym
    - Audit logging records the PSEUDONYM_IRREVERSIBLE_CREATED event
    """
    # Attach the handler BEFORE making the request
    records = record_logs(LOGGER_NAME)

    org, priv_key = irreversible_pseudonym_recipient_org

    response = client.post(
        ENDPOINT,
        json=irreversible_pseudonym_request_body,
        headers=irreversible_pseudonym_headers,
    )

    # Verify response status and headers
    assert response.status_code == 201
    assert response.headers["content-type"] == "application/jwe"

    # Decrypt and verify JWE/JWS

    _, _, claims = decrypt_signed(response.text, priv_key, jwt_signing_service)

    # Verify claims
    assert claims["subject"].startswith("pseudonym:irreversible:")
    assert claims["aud"] == f"oin:{org.external_id.value}"
    assert claims["scope"] == TEST_SCOPE
    assert claims["keyVersion"] == 1
    assert "extraVersions" not in claims

    # Verify audit logging by event_id (220401 = PSEUDONYM_IRREVERSIBLE_CREATED)
    created_events = [r for r in records if getattr(r, "event_id", None) == "220401"]
    assert len(created_events) == 1


def test_pseudonym_is_deterministic_and_accepts_both_personal_id_forms(
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that the same input produces the same pseudonym, and both string and dict personal ID formats work."""
    org, priv_key = irreversible_pseudonym_recipient_org

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
        headers=irreversible_pseudonym_headers,
    )
    dict_response = client.post(
        ENDPOINT,
        json=dict_body,
        headers=irreversible_pseudonym_headers,
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


def test_with_jwt_signing_returns_signed_irreversible_pseudonym(
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_request_body: dict[str, Any],
    irreversible_pseudonym_headers: dict[str, str],
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that the response includes a signed JWS when JWT signing is enabled."""
    org, priv_key = irreversible_pseudonym_recipient_org

    response = client.post(
        ENDPOINT,
        json=irreversible_pseudonym_request_body,
        headers=irreversible_pseudonym_headers,
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
    jwt_issuer = JWT_ISSUER
    assert claims["iss"] == jwt_issuer
    assert claims["subject"].startswith("pseudonym:irreversible:")
    assert claims["aud"] == f"oin:{org.external_id.value}"


def test_pseudonym_differs_per_personal_id(
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
    mock_personal_id_2: PersonalId,
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that different personal IDs produce different irreversible pseudonyms."""
    org, priv_key = irreversible_pseudonym_recipient_org

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
        headers=irreversible_pseudonym_headers,
    )
    second_response = client.post(
        ENDPOINT,
        json=second_body,
        headers=irreversible_pseudonym_headers,
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
    "value",
    ["not-a-pseudonym", "pseudonym:irreversible:AQAB"],
    ids=["garbage", "irreversible-subject"],
)
def test_garbage_reversible_pseudonym_is_refused(
    value: str,
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_headers: dict[str, str],
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that garbage reversible pseudonyms are refused with a 400 error."""
    org, _ = irreversible_pseudonym_recipient_org
    records = record_logs(LOGGER_NAME)

    request_body = {
        "reversiblePseudonym": value,
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=irreversible_pseudonym_headers,
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}

    failed_events = [r for r in records if getattr(r, "event_id", None) == "220403"]
    assert len(failed_events) == 1


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
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_headers: dict[str, str],
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    jwt_signing_service: JwtSigningService,
    mock_personal_id: PersonalId,
) -> None:
    """Tests that a reversible pseudonym from the caller's own organization is accepted as input."""
    # Get the sender org OIN from the headers
    sender_oin = Oin(irreversible_pseudonym_headers["x-gf-sub"])

    # Generate a reversible pseudonym for the sender org
    reversible_pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        sender_oin,
        "own-scope",  # Any scope, since it's for the sender
    )

    # Request with the reversible pseudonym (bare or prefixed)
    request_body = {
        **as_input(reversible_pseudonym.value),
        "recipientOrganization": f"oin:{irreversible_pseudonym_recipient_org[0].external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Request with the personal ID directly
    personal_id_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{irreversible_pseudonym_recipient_org[0].external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    # Make both requests
    from_personal_id = client.post(
        ENDPOINT,
        json=personal_id_body,
        headers=irreversible_pseudonym_headers,
    )
    from_pseudonym = client.post(
        ENDPOINT,
        json=request_body,
        headers=irreversible_pseudonym_headers,
    )

    # Both should succeed
    assert from_personal_id.status_code == 201
    assert from_pseudonym.status_code == 201

    # Decrypt both responses
    _, _, from_personal_id_claims = decrypt_signed(
        from_personal_id.text,
        irreversible_pseudonym_recipient_org[1],
        jwt_signing_service,
    )
    _, _, from_pseudonym_claims = decrypt_signed(
        from_pseudonym.text,
        irreversible_pseudonym_recipient_org[1],
        jwt_signing_service,
    )

    # The pseudonyms should be identical
    assert from_personal_id_claims["subject"] == from_pseudonym_claims["subject"]


@pytest.mark.parametrize(
    "personal_id,kind",
    [
        ("NL:passport:950000012", "formaat"),  # Wrong ID type
        ("NL:bsn:95000001", "lengte"),  # Wrong length
        ("NL:bsn:950000013", "elfproef"),  # Fails elfproef
    ],
    ids=["wrong_format", "wrong_length", "elfproef_failure"],
)
def test_malformed_personal_id_is_rejected_and_audited_without_the_value(
    personal_id: str,
    kind: str,
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_headers: dict[str, str],
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that malformed personal IDs are rejected and the value is not logged."""
    org, _ = irreversible_pseudonym_recipient_org
    records = record_logs(LOGGER_NAME)

    request_body = {
        "personalId": personal_id,
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=irreversible_pseudonym_headers,
    )

    # Should return 400
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid personal ID"}

    # Verify audit logging (PERSONAL_ID_VALIDATION_FAILED with event_id 220404)
    failed_events = [r for r in records if getattr(r, "event_id", None) == "220404"]
    assert len(failed_events) == 1
    assert failed_events[0].validation_error == kind  # type: ignore

    # Verify the personal ID value is NOT in any log record
    for record in records:
        assert personal_id.split(":")[-1] not in str(record.msg)


def test_reversible_pseudonym_of_another_organization_is_refused(
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_headers: dict[str, str],
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a reversible pseudonym from another organization is refused."""
    # Generate a reversible pseudonym for the RECIPIENT org (not the sender)
    recipient_oin = irreversible_pseudonym_recipient_org[0].external_id
    reversible_pseudonym = local_reversible_pseudonym_service.generate(
        PersonalId.from_str("NL:bsn:999990020"),
        recipient_oin,
        TEST_SCOPE,
    )

    records = record_logs(LOGGER_NAME)

    request_body = {
        "reversiblePseudonym": reversible_pseudonym.value,
        "recipientOrganization": f"oin:{recipient_oin.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=irreversible_pseudonym_headers,
    )

    # Should return 400
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}

    # Verify audit logging (PSEUDONYM_CREATE_FAILED with event_id 220403)
    failed_events = [r for r in records if getattr(r, "event_id", None) == "220403"]
    assert len(failed_events) == 1
    assert failed_events[0].error_type == "invalid_pseudonym"  # type: ignore


@pytest.mark.parametrize(
    "fields",
    [{}, {"personalId": "NL:bsn:999990020", "reversiblePseudonym": "AQAB"}],
    ids=["neither", "both"],
)
def test_not_exactly_one_input_is_rejected_without_echoing_it(
    fields: dict[str, str],
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_headers: dict[str, str],
) -> None:
    """Tests that exactly one of personalId or reversiblePseudonym is required."""
    org, _ = irreversible_pseudonym_recipient_org

    request_body = {
        **fields,
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=irreversible_pseudonym_headers,
    )

    # Should return 422 (Unprocessable Entity)
    assert response.status_code == 422

    # Verify the input is NOT echoed in the response
    assert "NL:bsn:999990020" not in response.text
    assert "AQAB" not in response.text


def test_dual_version_during_grace_returns_both_and_is_audited(
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_headers: dict[str, str],
    hsm_key_version_service: HsmKeyVersionService,
    jwt_signing_service: JwtSigningService,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that during a grace period, both old and new pseudonyms are returned."""
    org, priv_key = irreversible_pseudonym_recipient_org

    # Get the first pseudonym (before grace period)
    first_request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }
    first_response = client.post(
        ENDPOINT,
        json=first_request_body,
        headers=irreversible_pseudonym_headers,
    )
    assert first_response.status_code == 201

    _, _, first_claims = decrypt_signed(
        first_response.text, priv_key, jwt_signing_service
    )
    old_subject = first_claims["subject"]

    # Increase the key version for the recipient org (simulate grace period)
    hsm_key_version_service.increase_version_for_org(org.external_id)

    # Attach the handler BEFORE making the request
    records = record_logs(LOGGER_NAME)

    # Get the second pseudonym (during grace period)
    second_response = client.post(
        ENDPOINT,
        json=first_request_body,
        headers=irreversible_pseudonym_headers,
    )
    assert second_response.status_code == 201

    _, _, second_claims = decrypt_signed(
        second_response.text, priv_key, jwt_signing_service
    )
    new_subject = second_claims["subject"]

    # The new pseudonym should be different
    assert new_subject != old_subject

    # The response should include both versions
    assert second_claims["keyVersion"] == 2
    assert "extraVersions" in second_claims
    assert second_claims["extraVersions"] == {
        "1": old_subject.removeprefix("pseudonym:irreversible:")
    }

    # Verify audit logging (PSEUDONYM_IRREVERSIBLE_DUAL_CREATED with event_id 220402)
    dual_events = [r for r in records if getattr(r, "event_id", None) == "220402"]
    assert len(dual_events) == 1
    assert dual_events[0].previous_key_version == 1  # type: ignore[attr-defined]
    assert dual_events[0].current_key_version == 2  # type: ignore
    assert dual_events[0].domain == TEST_SCOPE  # type: ignore[attr-defined]


def test_sender_not_allowed_to_request_is_refused_before_anything_else(
    client: TestClient,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    irreversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
    db_session: DbSession,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that an unauthorized sender is refused before any processing."""
    # Create a sender org that is NOT allowed to request IRREVERSIBLE_PSEUDONYM
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.REVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    unauthorized_sender = OrganizationEntity(
        external_id=Oin("00000099000000004000"),  # New OIN
        name="unauthorized sender org",
        receive_personal_id_types=[],
        request_personal_id_types=list(personal_ids),  # Only reversible
        hsm_key_versions=[HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))],
    )
    db_session.add(unauthorized_sender)
    db_session.commit()

    # Use the unauthorized sender in the headers
    headers = {
        **irreversible_pseudonym_headers,
        "x-gf-sub": unauthorized_sender.external_id.value,  # Override sender
    }

    # Attach the handler BEFORE making the request
    records = record_logs(LOGGER_NAME)

    org, _ = irreversible_pseudonym_recipient_org
    request_body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{org.external_id.value}",
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
    assert denied_events[0].requested_operation == "exchange:irreversible-pseudonym"  # type: ignore


def test_recipient_not_allowed_to_receive_is_refused(
    client: TestClient,
    irreversible_pseudonym_headers: dict[str, str],
    mock_personal_id: PersonalId,
    db_session: DbSession,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a recipient org not allowed to receive irreversible pseudonyms is refused."""
    # Create a recipient org that is NOT allowed to receive IRREVERSIBLE_PSEUDONYM
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.REVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    unauthorized_recipient = OrganizationEntity(
        external_id=Oin("00000099000000005000"),  # New OIN
        name="unauthorized recipient org",
        receive_personal_id_types=list(personal_ids),  # Only reversible
        request_personal_id_types=[],
        hsm_key_versions=[HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))],
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
        headers=irreversible_pseudonym_headers,
    )

    # Should return 404
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }

    # Verify audit logging (AUTHORIZATION_DENIED with event_id 200402)
    denied_events = [r for r in records if getattr(r, "event_id", None) == "200402"]
    assert len(denied_events) == 1


def test_recipient_without_public_key_for_scope_is_not_found(
    client: TestClient,
    irreversible_pseudonym_headers: dict[str, str],
    db_session: DbSession,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a recipient org without a public key for the scope is refused."""
    # Create a recipient org with IRREVERSIBLE_PSEUDONYM type and key versions
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.IRREVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    recipient_org = OrganizationEntity(
        external_id=Oin("00000099000000006000"),  # New OIN
        name="recipient without public key for scope",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=[],
        hsm_key_versions=[HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))],
    )
    db_session.add(recipient_org)
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
        headers=irreversible_pseudonym_headers,
    )

    # Should return 404
    assert response.status_code == 404
    assert response.json() == {"detail": "Organization domain is not registered"}

    # Verify audit logging (EXCHANGE_REFUSED_NO_ACTIVE_PUBKEY with event_id 220407)
    refused_events = [r for r in records if getattr(r, "event_id", None) == "220407"]
    assert len(refused_events) == 1


def test_recipient_without_active_key_version_is_not_found(
    client: TestClient,
    irreversible_pseudonym_headers: dict[str, str],
    db_session: DbSession,
    organization_public_key_service: OrganizationPublicKeyService,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a recipient org without an active key version is refused."""
    # Create a recipient org with IRREVERSIBLE_PSEUDONYM type but NO active key versions
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.IRREVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    recipient_org = OrganizationEntity(
        external_id=Oin("00000099000000007000"),  # New OIN
        name="recipient without active key version",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=[],
        hsm_key_versions=[],  # No key versions
    )
    db_session.add(recipient_org)
    db_session.commit()

    # Add a public key for the scope (so the public key check passes)
    setup_org_and_key(organization_public_key_service, recipient_org, [TEST_SCOPE])

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
        headers=irreversible_pseudonym_headers,
    )

    # Should return 404
    assert response.status_code == 404
    assert response.json() == {
        "detail": "Unable to find requested recipient organization"
    }

    # Verify audit logging (PSEUDONYM_CREATE_FAILED with event_id 220403)
    failed_events = [r for r in records if getattr(r, "event_id", None) == "220403"]
    assert len(failed_events) == 1
    assert failed_events[0].error_type == "no_active_key_version"  # type: ignore


def test_reversible_pseudonym_with_destroyed_key_version_is_gone(
    client: TestClient,
    irreversible_pseudonym_headers: dict[str, str],
    db_session: DbSession,
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    organization_public_key_service: OrganizationPublicKeyService,
    hsm_key_version_service: HsmKeyVersionService,
    mock_personal_id: PersonalId,
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    """Tests that a reversible pseudonym with a destroyed key version is gone (410)."""
    # Get the sender org OIN from the headers
    sender_oin = Oin(irreversible_pseudonym_headers["x-gf-sub"])

    # Generate a reversible pseudonym for the sender org
    reversible_pseudonym = local_reversible_pseudonym_service.generate(
        mock_personal_id,
        sender_oin,
        "own-scope",
    )

    # Create a recipient org with IRREVERSIBLE_PSEUDONYM type and key versions
    personal_ids = (
        db_session.execute(
            select(PersonalIdTypeEntity).where(
                PersonalIdTypeEntity.name == str(PersonalIdType.IRREVERSIBLE_PSEUDONYM)
            )
        )
        .scalars()
        .all()
    )
    recipient_org = OrganizationEntity(
        external_id=Oin("00000099000000008000"),  # New OIN
        name="recipient org for destroyed key version test",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=[],
        hsm_key_versions=[HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))],
    )
    db_session.add(recipient_org)
    db_session.commit()

    # Add a public key for the scope
    setup_org_and_key(organization_public_key_service, recipient_org, [TEST_SCOPE])

    # Destroy all key versions for the sender org
    for version in hsm_key_version_service.get_versions_by_organization_id(sender_oin):
        hsm_key_version_service.mark_removed(version.id)

    # Attach the handler BEFORE making the request
    records = record_logs(LOGGER_NAME)

    request_body = {
        "reversiblePseudonym": reversible_pseudonym.value,
        "recipientOrganization": f"oin:{recipient_org.external_id.value}",
        "recipientScope": TEST_SCOPE,
    }

    response = client.post(
        ENDPOINT,
        json=request_body,
        headers=irreversible_pseudonym_headers,
    )

    # Should return 410
    assert response.status_code == 410
    assert response.json() == {"detail": "Pseudonym key version no longer available"}

    # Verify audit logging (PSEUDONYM_CREATE_FAILED with event_id 220403)
    failed_events = [r for r in records if getattr(r, "event_id", None) == "220403"]
    assert len(failed_events) == 1
    assert failed_events[0].error_type == "version_destroyed"  # type: ignore


def test_requires_the_pseudonym_scope(
    client: TestClient,
    irreversible_pseudonym_sender_org: OrganizationEntity,
    irreversible_pseudonym_recipient_org: tuple[OrganizationEntity, str],
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    expected_audiences: list[str],
    mock_personal_id: PersonalId,
) -> None:
    """Tests that the prs:pseudonym scope is required to request irreversible pseudonyms."""
    org, _ = irreversible_pseudonym_recipient_org

    # Helper to build headers with custom scopes
    def build_headers(scopes: list[AuthorizationScope]) -> dict[str, str]:
        return {
            "x-gf-sub": irreversible_pseudonym_sender_org.external_id.value,
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
