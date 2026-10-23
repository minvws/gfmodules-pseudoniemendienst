import json
from dataclasses import dataclass

import pytest
from fastapi import Depends, FastAPI
from jwcrypto import jwk
from pytest_mock import MockerFixture
from starlette.testclient import TestClient

from app.auth import get_auth_ctx
from app.container import (
    get_auth_headers_service,
    get_authorization_service,
    get_hsm_key_version_service,
    get_jwe_token_service,
    get_jwt_signing_service,
    get_oprf_service,
    get_organization_public_key_service,
)
from app.db.models import OrganizationEntity
from app.routers import test_oprf
from app.routers.errors import (
    install_app_error_handler,
    install_validation_error_handler,
)
from app.routers.health import router as health_router
from app.routers.oprf import router as oprf_router
from app.routers.test_oprf import router as test_oprf_router
from app.services.auth.header import AuthHeaderService
from app.services.authorization_service import AuthorizationService
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.jwe_token import JweTokenService
from app.services.jwt_signer import JwtSigningService
from app.services.oprf.evaluators import LocalOprfEvaluator
from app.services.oprf.oprf_service import OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from tests.conftest import (
    JWT_ISSUER,
    decrypt_signed,
    generate_rsa_keypair,
    setup_org_and_key,
)

# ==================== FIXTURES ====================


@dataclass(frozen=True)
class OprfTestRouterContext:
    oprf_input: str
    recipient_organization: str
    recipient_scope: str
    private_key_pem: str


@pytest.fixture
def oprf_test_router_context(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> OprfTestRouterContext:
    """Sets up a test organization with a public key for the OPRF test scope."""
    recipient_domain = "nvi"
    private_key_pem = setup_org_and_key(
        organization_public_key_service=organization_public_key_service,
        organization=persisted_organization,
        domains=[recipient_domain],
    )
    return OprfTestRouterContext(
        oprf_input="could_be_personal_id_or_not",
        recipient_organization=f"oin:{persisted_organization.external_id.value}",
        recipient_scope=recipient_domain,
        private_key_pem=private_key_pem,
    )


# ==================== APP SETUP ====================


@pytest.fixture()
def oprf_test_router_app(
    local_oprf_evaluator: LocalOprfEvaluator,
    hsm_key_version_service: HsmKeyVersionService,
    organization_public_key_service: OrganizationPublicKeyService,
    authorization_service: AuthorizationService,
    auth_headers_service: AuthHeaderService,
    # Use the fixture directly (local keys, enabled)
    jwt_signing_service: JwtSigningService,
) -> FastAPI:
    """Minimal FastAPI app for OPRF test router, using local evaluator."""

    app = FastAPI()

    # Include routers
    app.include_router(health_router)
    app.include_router(test_oprf_router, dependencies=[Depends(get_auth_ctx)])
    app.include_router(oprf_router)

    # Install error handlers
    install_validation_error_handler(app)
    install_app_error_handler(app)

    # Create JWE token service with JWT signing enabled (uses local keys)
    jwe_token_service = JweTokenService(jwt_signing_service)

    # Create OPRF service with LOCAL evaluator (no HSM)
    oprf_service = OprfService(
        evaluator=local_oprf_evaluator,
        jwe_token_service=jwe_token_service,
    )

    # Override dependencies
    app.dependency_overrides[get_oprf_service] = lambda: oprf_service
    app.dependency_overrides[get_jwe_token_service] = lambda: jwe_token_service
    app.dependency_overrides[get_hsm_key_version_service] = lambda: (
        hsm_key_version_service
    )
    app.dependency_overrides[get_organization_public_key_service] = lambda: (
        organization_public_key_service
    )
    app.dependency_overrides[get_authorization_service] = lambda: authorization_service
    app.dependency_overrides[get_auth_headers_service] = lambda: auth_headers_service
    app.dependency_overrides[get_jwt_signing_service] = lambda: jwt_signing_service

    return app


@pytest.fixture()
def oprf_test_router_client(oprf_test_router_app: FastAPI) -> TestClient:
    """TestClient for the OPRF test router app."""
    return TestClient(oprf_test_router_app)


# ==================== HELPER FUNCTION ====================


def _blind_and_evaluate(
    client: TestClient,
    context: OprfTestRouterContext,
    headers: dict[str, str],
) -> tuple[str, str]:
    """Blinds a personal ID and evaluates it via OPRF, returning (blind_factor, jwe_token)."""
    client_response = client.post(
        "/test/oprf/client",
        json={"personalId": context.oprf_input},
        headers=headers,
    )
    assert client_response.status_code == 200

    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": client_response.json()["blinded_input"],
            "recipientOrganization": context.recipient_organization,
            "recipientScope": context.recipient_scope,
        },
        headers=headers,
    )
    assert eval_response.status_code == 200
    return client_response.json()["blind_factor"], eval_response.json()["jwe"]


# ==================== TESTS ====================


def test_test_oprf_client_and_receiver_roundtrip(
    oprf_test_router_client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
) -> None:
    """Tests the full roundtrip: client → eval → receiver."""
    blind_factor, jwe_token = _blind_and_evaluate(
        oprf_test_router_client, oprf_test_router_context, valid_headers
    )

    receiver_response = oprf_test_router_client.post(
        "/test/oprf/receiver",
        json={
            "blind_factor": blind_factor,
            "jwe": jwe_token,
            "priv_key_pem": oprf_test_router_context.private_key_pem,
        },
        headers=valid_headers,
    )
    assert receiver_response.status_code == 200

    body = receiver_response.json()
    assert (
        body["jwe"]["decrypted"]["aud"]
        == oprf_test_router_context.recipient_organization
    )
    assert body["jwe"]["decrypted"]["scope"] == oprf_test_router_context.recipient_scope
    assert body["eval_subject"]
    assert body["final_pseudonym"]
    assert body["jwe"]["headers"]["cty"] == "JWT"
    assert body["jws"] is not None
    assert body["jws"]["signature"] == "valid"


def test_with_jwt_signing_oprf_eval_is_signed_and_test_routes_verify_it(
    oprf_test_router_client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
    jwt_signing_service: JwtSigningService,
) -> None:
    """Tests that OPRF eval returns a signed JWE when JWT signing is enabled."""
    ctx = oprf_test_router_context
    blinded = oprf_test_router_client.post(
        "/test/oprf/client", json={"personalId": ctx.oprf_input}, headers=valid_headers
    ).json()

    eval_response = oprf_test_router_client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded["blinded_input"],
            "recipientOrganization": ctx.recipient_organization,
            "recipientScope": ctx.recipient_scope,
        },
        headers=valid_headers,
    )
    assert eval_response.status_code == 200
    jwe_token = eval_response.json()["jwe"]

    # Decrypt and verify JWE/JWS
    _, _, claims = decrypt_signed(jwe_token, ctx.private_key_pem, jwt_signing_service)
    assert claims["iss"] == JWT_ISSUER
    assert claims["subject"].startswith("pseudonym:eval:")

    # Verify receiver can decrypt and finalize
    receiver = oprf_test_router_client.post(
        "/test/oprf/receiver",
        json={
            "blind_factor": blinded["blind_factor"],
            "jwe": jwe_token,
            "priv_key_pem": ctx.private_key_pem,
        },
        headers=valid_headers,
    ).json()
    assert receiver["jwe"]["headers"]["cty"] == "JWT"
    assert receiver["jws"]["headers"]["kid"] == jwt_signing_service.active.kid
    assert receiver["jws"]["signature"] == "valid"
    assert receiver["jwe"]["decrypted"]["iss"] == JWT_ISSUER
    assert receiver["final_pseudonym"]

    # Verify JWE decode
    decoded = oprf_test_router_client.post(
        "/test/jwe/decode",
        json={"jwe": jwe_token, "priv_key_pem": ctx.private_key_pem},
        headers=valid_headers,
    ).json()
    assert decoded["jws"]["signature"] == "valid"
    assert decoded["jwe"]["decrypted"]["subject"] == claims["subject"]


def test_test_oprf_receiver_incorrect_private_key(
    oprf_test_router_client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
) -> None:
    """Tests that using the wrong private key fails to decrypt the JWE."""
    blind_factor, jwe_token = _blind_and_evaluate(
        oprf_test_router_client, oprf_test_router_context, valid_headers
    )
    other_private_key_pem, _ = generate_rsa_keypair()

    receiver_response = oprf_test_router_client.post(
        "/test/oprf/receiver",
        json={
            "blind_factor": blind_factor,
            "jwe": jwe_token,
            "priv_key_pem": other_private_key_pem,
        },
        headers=valid_headers,
    )
    assert receiver_response.status_code == 200

    body = receiver_response.json()
    assert body["jwe"]["decrypted"].startswith("Could not decrypt JWE:")
    assert body["eval_subject"] == "unknown"
    assert body["final_pseudonym"] == "unknown"


def test_test_oprf_receiver_invalid_private_key(
    oprf_test_router_client: TestClient,
    valid_headers: dict[str, str],
) -> None:
    """Tests that an invalid private key is rejected with 422."""
    receiver_response = oprf_test_router_client.post(
        "/test/oprf/receiver",
        json={
            "blind_factor": "ZmFrZS1mYWN0b3I=",
            "jwe": "a.b.c.d.e",
            "priv_key_pem": "-----BEGIN PRIVATE KEY-----invalid",
        },
        headers=valid_headers,
    )
    assert receiver_response.status_code == 422


@pytest.mark.parametrize("path", ["/test/oprf/receiver", "/test/jwe/decode"])
def test_test_endpoints_parse_private_key_once(
    path: str,
    oprf_test_router_client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
    mocker: MockerFixture,
) -> None:
    """Tests that the private key is parsed only once per request."""
    ctx = oprf_test_router_context
    blind_factor, jwe_token = _blind_and_evaluate(
        oprf_test_router_client, ctx, valid_headers
    )
    load_key = mocker.spy(test_oprf, "load_pem_private_key")
    payload = {"jwe": jwe_token, "priv_key_pem": ctx.private_key_pem}
    if path == "/test/oprf/receiver":
        payload["blind_factor"] = blind_factor

    response = oprf_test_router_client.post(path, json=payload, headers=valid_headers)

    assert response.status_code == 200
    assert response.json()["priv_key_pem"] == ctx.private_key_pem
    assert response.json()["jwe"]["decrypted"]["aud"] == ctx.recipient_organization
    assert load_key.call_count == 1


@pytest.mark.parametrize("path", ["/test/oprf/receiver", "/test/jwe/decode"])
def test_test_endpoints_reject_unexpected_fields(
    path: str,
    oprf_test_router_client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
) -> None:
    ctx = oprf_test_router_context
    blind_factor, jwe_token = _blind_and_evaluate(
        oprf_test_router_client, ctx, valid_headers
    )
    payload = {
        "jwe": jwe_token,
        "priv_key_pem": ctx.private_key_pem,
        "unexpected": "value",
    }
    if path == "/test/oprf/receiver":
        payload["blind_factor"] = blind_factor

    response = oprf_test_router_client.post(path, json=payload, headers=valid_headers)

    assert response.status_code == 422
    assert response.json()["detail"] == [
        {
            "type": "extra_forbidden",
            "loc": ["body", "unexpected"],
            "msg": "Extra inputs are not permitted",
        }
    ]


@pytest.mark.parametrize(
    "request_type", [test_oprf.JweReceiverRequest, test_oprf.ReceiverRequest]
)
def test_jwe_request_schema_forbids_extra_fields(
    request_type: type[test_oprf.JweReceiverRequest],
) -> None:
    assert request_type.model_json_schema().get("additionalProperties") is False


def test_jwe_receiver_request_retains_and_serializes_private_key() -> None:
    pem, _ = generate_rsa_keypair()
    request = test_oprf.JweReceiverRequest.model_validate(
        {"jwe": "a.b.c.d.e", "priv_key_pem": pem}
    )

    assert request.private_key.pem == pem
    assert isinstance(request.private_key.key, jwk.JWK)
    assert pem not in repr(request.private_key)
    assert request.model_dump()["priv_key_pem"] == pem
    assert request.model_dump(by_alias=False)["private_key"] == pem
    assert request.model_dump(by_alias=True)["priv_key_pem"] == pem
    assert json.loads(request.model_dump_json())["priv_key_pem"] == pem
    schema = request.model_json_schema(mode="validation")
    assert schema["properties"]["priv_key_pem"]["type"] == "string"
    schema = request.model_json_schema(mode="serialization")
    assert schema["properties"]["priv_key_pem"]["type"] == "string"


def test_test_oprf_receiver_rejects_public_key(
    oprf_test_router_client: TestClient, valid_headers: dict[str, str]
) -> None:
    _, public_pem = generate_rsa_keypair()
    response = oprf_test_router_client.post(
        "/test/oprf/receiver",
        json={
            "jwe": "a.b.c.d.e",
            "blind_factor": "ZmFrZS1mYWN0b3I=",
            "priv_key_pem": public_pem,
        },
        headers=valid_headers,
    )

    assert response.status_code == 422
    assert public_pem not in response.text
