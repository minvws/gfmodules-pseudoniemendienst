"""Integration tests for authorization scope validation.

These tests verify that the correct authorization scopes are enforced
for various endpoints, including OPRF, administration, and reversible pseudonym routes.
"""

from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from starlette.testclient import TestClient

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.enums.personal_id_type import PersonalIdType
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.services.organization_public_key_service import OrganizationPublicKeyService
from tests.conftest import personal_id_types, setup_org_and_key


def test_missing_scope_header_is_rejected(
    client: TestClient,
    valid_headers: dict[str, str],
    valid_organization_id: Oin,
) -> None:
    """Tests that a request without the x-gf-scope header is rejected with 403."""
    # Remove the x-gf-scope header
    headers = {k: v for k, v in valid_headers.items() if k != "x-gf-scope"}

    # Use test_oin for the recipientOrganization
    oprf_body = {
        "encryptedPersonalId": "Zm9v",
        "recipientOrganization": f"oin:{valid_organization_id.value}",
        "recipientScope": "nvi",
    }

    response = client.post("/oprf/eval", json=oprf_body, headers=headers)

    assert response.status_code == 403


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_scope_header_is_rejected(
    client: TestClient,
    valid_headers: dict[str, str],
    valid_organization_id: Oin,
    value: str,
) -> None:
    """Tests that a request with an empty or whitespace-only x-gf-scope header is rejected with 403."""
    oprf_body = {
        "encryptedPersonalId": "Zm9v",
        "recipientOrganization": f"oin:{valid_organization_id.value}",
        "recipientScope": "nvi",
    }

    response = client.post(
        "/oprf/eval",
        json=oprf_body,
        headers={**valid_headers, "x-gf-scope": value},
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "value",
    [
        "prs:read",
        "prs:create prs:read",
        "nvi:read",
        "prs:administration_typo",
    ],
)
def test_scope_header_without_a_known_scope_is_rejected(
    client: TestClient,
    valid_headers: dict[str, str],
    valid_organization_id: Oin,
    value: str,
) -> None:
    """Tests that a request with a scope header containing unknown scopes is rejected with 403."""
    oprf_body = {
        "encryptedPersonalId": "Zm9v",
        "recipientOrganization": f"oin:{valid_organization_id.value}",
        "recipientScope": "nvi",
    }
    headers = {**valid_headers, "x-gf-scope": value}

    # Test OPRF endpoint
    assert client.post("/oprf/eval", json=oprf_body, headers=headers).status_code == 403
    # Test administration endpoint
    assert client.get("/administration/keys", headers=headers).status_code == 403


@pytest.mark.parametrize(
    "value",
    [
        "prs:oprf-pseudonym prs:read",
        "nvi:read prs:oprf-pseudonym",
        "nvi:read prs:oprf-pseudonym lmr:write",
    ],
)
def test_unknown_scopes_are_ignored_alongside_a_known_one(
    client: TestClient,
    valid_headers: dict[str, str],
    valid_organization_id: Oin,
    persisted_organization: OrganizationEntity,
    value: str,
) -> None:
    """Tests that unknown scopes are ignored if a known scope is also present."""
    oprf_body = {
        "encryptedPersonalId": "Zm9v",
        "recipientOrganization": f"oin:{valid_organization_id.value}",
        "recipientScope": "nvi",
    }
    headers = {**valid_headers, "x-gf-scope": value}

    # OPRF endpoint should succeed (prs:oprf-pseudonym is valid)
    assert client.post("/oprf/eval", json=oprf_body, headers=headers).status_code != 403
    # Administration endpoint should fail (no prs:administration scope)
    assert client.get("/administration/keys", headers=headers).status_code == 403


def test_scope_header_accepts_extra_whitespace(
    client: TestClient,
    valid_headers: dict[str, str],
    valid_organization_id: Oin,
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that the x-gf-scope header accepts extra whitespace."""
    headers = {
        **valid_headers,
        "x-gf-scope": "  prs:oprf-pseudonym   prs:pseudonym  ",
    }

    oprf_body = {
        "encryptedPersonalId": "Zm9v",
        "recipientOrganization": f"oin:{valid_organization_id.value}",
        "recipientScope": "nvi",
    }

    response = client.post("/oprf/eval", json=oprf_body, headers=headers)

    assert response.status_code != 403


def test_oprf_eval_requires_the_oprf_scope(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    persisted_organization: OrganizationEntity,
) -> None:
    """Tests that the /oprf/eval endpoint requires the prs:oprf-pseudonym scope."""

    oprf_body = {
        "encryptedPersonalId": "Zm9v",
        "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
        "recipientScope": "nvi",
    }

    # Without OPRF scope (only ADMINISTRATION)
    without = headers_with_scopes(AuthorizationScope.ADMINISTRATION)
    assert client.post("/oprf/eval", json=oprf_body, headers=without).status_code == 403

    # With OPRF scope
    granted = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)
    assert client.post("/oprf/eval", json=oprf_body, headers=granted).status_code != 403


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/administration/keys"),
        ("get", "/administration/key-versions"),
        ("post", "/administration/key-versions"),
    ],
)
def test_administration_routes_require_the_administration_scope(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    persisted_organization: OrganizationEntity,
    method: str,
    path: str,
) -> None:
    """Tests that administration routes require the prs:administration scope."""
    # Without ADMINISTRATION scope (only OPRF_PSEUDONYM and PSEUDONYM)
    without = headers_with_scopes(
        AuthorizationScope.OPRF_PSEUDONYM,
        AuthorizationScope.PSEUDONYM,
    )
    assert client.request(method, path, headers=without).status_code == 403

    # With ADMINISTRATION scope
    granted = headers_with_scopes(AuthorizationScope.ADMINISTRATION)
    assert client.request(method, path, headers=granted).status_code != 403


def test_test_routes_are_authenticated_but_not_scoped(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    mock_personal_id: PersonalId,
) -> None:
    """Tests that test routes are authenticated but do not enforce scopes."""

    # With valid headers (including x-gf-sub)
    headers = headers_with_scopes(AuthorizationScope.ADMINISTRATION)
    # Use as_str() or as_dict()
    body = {"personalId": mock_personal_id.as_str()}
    assert (
        client.post("/test/oprf/client", json=body, headers=headers).status_code == 200
    )

    # Without x-gf-sub (unauthenticated)
    unauthenticated = {k: v for k, v in headers.items() if k != "x-gf-sub"}
    assert (
        client.post("/test/oprf/client", json=body, headers=unauthenticated).status_code
        == 403
    )


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/exchange/irreversible-pseudonym"),
        ("post", "/exchange/reversible-pseudonym"),
    ],
)
def test_exchange_routes_require_authentication(
    client: TestClient,
    db_session: DbSession,
    organization_public_key_service: OrganizationPublicKeyService,
    valid_headers: dict[str, str],
    mock_personal_id: PersonalId,
    method: str,
    path: str,
) -> None:
    """Tests that exchange routes require authentication (x-gf-sub header)."""

    # Create a test organization with all personal ID types
    id_types = personal_id_types(
        db_session,
        [PersonalIdType.REVERSIBLE_PSEUDONYM, PersonalIdType.IRREVERSIBLE_PSEUDONYM],
    )
    test_org = OrganizationEntity(
        external_id=Oin("00000099000000003000"),  # Unique OIN
        name="test_org_exchange",
        receive_personal_id_types=list(id_types),
        request_personal_id_types=list(id_types),
        hsm_key_versions=[HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))],
    )
    db_session.add(test_org)
    db_session.commit()
    # Add a public key for the 'nvi' scope
    setup_org_and_key(organization_public_key_service, test_org, ["nvi"])

    # Update headers to use the new org as the caller
    test_headers = {
        **valid_headers,
        "x-gf-sub": str(test_org.external_id.value),
        "x-gf-act-sub": str(test_org.external_id.value),
    }

    body = {
        "personalId": mock_personal_id.as_str(),
        "recipientOrganization": f"oin:{test_org.external_id.value}",
        "recipientScope": "nvi",
    }

    # With valid headers (including x-gf-sub)
    assert (
        client.request(method, path, json=body, headers=test_headers).status_code == 201
    )

    # Without x-gf-sub (unauthenticated)
    unauthenticated = {k: v for k, v in test_headers.items() if k != "x-gf-sub"}
    assert (
        client.request(method, path, json=body, headers=unauthenticated).status_code
        == 403
    )


def test_exchange_reversible_pseudonym_requires_the_pseudonym_scope(
    client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    persisted_organization: OrganizationEntity,
    mock_personal_id: PersonalId,
) -> None:
    """Tests that /exchange/reversible-pseudonym requires the prs:pseudonym scope."""
    from app.models.auth.data import AuthorizationScope

    reversible_pseudonym_body = {
        "personalId": mock_personal_id.as_dict(),
        "recipientOrganization": f"oin:{persisted_organization.external_id.value}",
        "recipientScope": "nvi",
    }

    # Without PSEUDONYM scope (only OPRF_PSEUDONYM and ADMINISTRATION)
    without = headers_with_scopes(
        AuthorizationScope.OPRF_PSEUDONYM, AuthorizationScope.ADMINISTRATION
    )
    denied = client.post(
        "/exchange/reversible-pseudonym",
        json=reversible_pseudonym_body,
        headers=without,
    )
    assert denied.status_code == 403

    # With PSEUDONYM scope
    granted = headers_with_scopes(AuthorizationScope.PSEUDONYM)
    allowed = client.post(
        "/exchange/reversible-pseudonym",
        json=reversible_pseudonym_body,
        headers=granted,
    )
    # A policy refusal is also 403, so tell the two apart by the message: the
    # scope check answers "Unauthorized request", the router never does.
    assert allowed.json().get("detail") != "Unauthorized request"
