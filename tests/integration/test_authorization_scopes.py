"""Integration tests for authorization scope validation.

These tests verify that the correct authorization scopes are enforced
for various endpoints, including OPRF, administration, and reversible pseudonym routes.
"""

from collections.abc import Callable
from datetime import datetime, timezone

import pytest
from fastapi import Depends, FastAPI, Security
from starlette.testclient import TestClient

from app.auth import get_auth_ctx, require_scopes
from app.container import (
    get_auth_headers_service,
    get_authorization_service,
    get_hsm_key_version_service,
    get_irreversible_pseudonym_service,
    get_jwe_token_service,
    get_jwt_signing_service,
    get_oprf_service,
    get_organization_public_key_service,
    get_reversible_pseudonym_service,
)
from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.enums.personal_id_type import PersonalIdType
from app.models.auth.data import AuthorizationScope
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.routers.administration.hsm_key_version import router as hsm_key_version_router
from app.routers.administration.key import router as key_router
from app.routers.errors import (
    install_app_error_handler,
    install_validation_error_handler,
)
from app.routers.exchange.router import router as exchange_router
from app.routers.health import router as health_router
from app.routers.oprf import router as oprf_router
from app.routers.test_oprf import router as test_oprf_router
from app.services.auth.header import AuthHeaderService
from app.services.authorization_service import AuthorizationService
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.irreversible.service import IrreversiblePseudonymService
from app.services.jwe_token import JweTokenService
from app.services.jwt_signer import JwtSigningService
from app.services.oprf.oprf_service import OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversiblePseudonymService
from tests.conftest import personal_id_types, setup_org_and_key

# ==================== APP SETUP ====================


@pytest.fixture()
def auth_scopes_app(
    local_irreversible_pseudonym_service: IrreversiblePseudonymService,
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    hsm_key_version_service: HsmKeyVersionService,
    organization_public_key_service: OrganizationPublicKeyService,
    authorization_service: AuthorizationService,
    auth_headers_service: AuthHeaderService,
    jwt_signing_service: JwtSigningService,
    oprf_service: OprfService,
) -> FastAPI:
    """Minimal FastAPI app for authorization scope tests."""

    app = FastAPI()

    # Include routers
    app.include_router(health_router)
    app.include_router(exchange_router)
    app.include_router(oprf_router)
    app.include_router(test_oprf_router, dependencies=[Depends(get_auth_ctx)])

    # Administration routers (with scope enforcement)
    for router in [key_router, hsm_key_version_router]:
        app.include_router(
            router,
            prefix="/administration",
            dependencies=[
                Depends(get_auth_ctx),
                Security(
                    require_scopes, scopes=[AuthorizationScope.ADMINISTRATION.value]
                ),
            ],
        )

    # Install error handlers
    install_validation_error_handler(app)
    install_app_error_handler(app)

    # Create JWE token service
    jwe_token_service = JweTokenService(jwt_signing_service)

    # Override dependencies
    app.dependency_overrides[get_irreversible_pseudonym_service] = lambda: (
        local_irreversible_pseudonym_service
    )
    app.dependency_overrides[get_reversible_pseudonym_service] = lambda: (
        local_reversible_pseudonym_service
    )
    app.dependency_overrides[get_hsm_key_version_service] = lambda: (
        hsm_key_version_service
    )
    app.dependency_overrides[get_organization_public_key_service] = lambda: (
        organization_public_key_service
    )
    app.dependency_overrides[get_authorization_service] = lambda: authorization_service
    app.dependency_overrides[get_auth_headers_service] = lambda: auth_headers_service
    app.dependency_overrides[get_jwt_signing_service] = lambda: jwt_signing_service
    app.dependency_overrides[get_jwe_token_service] = lambda: jwe_token_service
    app.dependency_overrides[get_oprf_service] = lambda: oprf_service

    return app


@pytest.fixture()
def auth_scopes_client(auth_scopes_app: FastAPI) -> TestClient:
    """TestClient for the auth scopes app."""
    return TestClient(auth_scopes_app)


# ==================== TESTS ====================


def test_missing_scope_header_is_rejected(
    auth_scopes_client: TestClient,
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

    response = auth_scopes_client.post("/oprf/eval", json=oprf_body, headers=headers)

    assert response.status_code == 403


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_scope_header_is_rejected(
    auth_scopes_client: TestClient,
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

    response = auth_scopes_client.post(
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
    auth_scopes_client: TestClient,
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
    assert (
        auth_scopes_client.post(
            "/oprf/eval", json=oprf_body, headers=headers
        ).status_code
        == 403
    )
    # Test administration endpoint
    assert (
        auth_scopes_client.get("/administration/keys", headers=headers).status_code
        == 403
    )


@pytest.mark.parametrize(
    "value",
    [
        "prs:oprf-pseudonym prs:read",
        "nvi:read prs:oprf-pseudonym",
        "nvi:read prs:oprf-pseudonym lmr:write",
    ],
)
def test_unknown_scopes_are_ignored_alongside_a_known_one(
    auth_scopes_client: TestClient,
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
    assert (
        auth_scopes_client.post(
            "/oprf/eval", json=oprf_body, headers=headers
        ).status_code
        != 403
    )
    # Administration endpoint should fail (no prs:administration scope)
    assert (
        auth_scopes_client.get("/administration/keys", headers=headers).status_code
        == 403
    )


def test_scope_header_accepts_extra_whitespace(
    auth_scopes_client: TestClient,
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

    response = auth_scopes_client.post("/oprf/eval", json=oprf_body, headers=headers)

    assert response.status_code != 403


def test_oprf_eval_requires_the_oprf_scope(
    auth_scopes_client: TestClient,
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
    assert (
        auth_scopes_client.post(
            "/oprf/eval", json=oprf_body, headers=without
        ).status_code
        == 403
    )

    # With OPRF scope
    granted = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)
    assert (
        auth_scopes_client.post(
            "/oprf/eval", json=oprf_body, headers=granted
        ).status_code
        != 403
    )


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/administration/keys"),
        ("get", "/administration/key-versions"),
        ("post", "/administration/key-versions"),
    ],
)
def test_administration_routes_require_the_administration_scope(
    auth_scopes_client: TestClient,
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
    assert auth_scopes_client.request(method, path, headers=without).status_code == 403

    # With ADMINISTRATION scope
    granted = headers_with_scopes(AuthorizationScope.ADMINISTRATION)
    assert auth_scopes_client.request(method, path, headers=granted).status_code != 403


def test_test_routes_are_authenticated_but_not_scoped(
    auth_scopes_client: TestClient,
    headers_with_scopes: Callable[..., dict[str, str]],
    mock_personal_id: PersonalId,
) -> None:
    """Tests that test routes are authenticated but do not enforce scopes."""

    # With valid headers (including x-gf-sub)
    headers = headers_with_scopes(AuthorizationScope.ADMINISTRATION)
    # Use as_str() or as_dict()
    body = {"personalId": mock_personal_id.as_str()}
    assert (
        auth_scopes_client.post(
            "/test/oprf/client", json=body, headers=headers
        ).status_code
        == 200
    )

    # Without x-gf-sub (unauthenticated)
    unauthenticated = {k: v for k, v in headers.items() if k != "x-gf-sub"}
    assert (
        auth_scopes_client.post(
            "/test/oprf/client", json=body, headers=unauthenticated
        ).status_code
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
    auth_scopes_client: TestClient,
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
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
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
        auth_scopes_client.request(
            method, path, json=body, headers=test_headers
        ).status_code
        == 201
    )

    # Without x-gf-sub (unauthenticated)
    unauthenticated = {k: v for k, v in test_headers.items() if k != "x-gf-sub"}
    assert (
        auth_scopes_client.request(
            method, path, json=body, headers=unauthenticated
        ).status_code
        == 403
    )


def test_exchange_reversible_pseudonym_requires_the_pseudonym_scope(
    auth_scopes_client: TestClient,
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
    denied = auth_scopes_client.post(
        "/exchange/reversible-pseudonym",
        json=reversible_pseudonym_body,
        headers=without,
    )
    assert denied.status_code == 403

    # With PSEUDONYM scope
    granted = headers_with_scopes(AuthorizationScope.PSEUDONYM)
    allowed = auth_scopes_client.post(
        "/exchange/reversible-pseudonym",
        json=reversible_pseudonym_body,
        headers=granted,
    )
    # A policy refusal is also 403, so tell the two apart by the message: the
    # scope check answers "Unauthorized request", the router never does.
    assert allowed.json().get("detail") != "Unauthorized request"
