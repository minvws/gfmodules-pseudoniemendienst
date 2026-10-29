from dataclasses import dataclass

import pytest
from conftest import (
    JWT_ISSUER,
    decrypt_signed,
    generate_rsa_keypair,
    setup_org_and_key,
)
from starlette.testclient import TestClient

from app.db.models import OrganizationEntity
from app.models.oin import Oin
from app.services.jwt_signer import JwtSigningService
from app.services.organization_public_key_service import OrganizationPublicKeyService


@dataclass(frozen=True)
class OprfTestRouterContext:
    oprf_input: str
    recipient_organization: str
    recipient_scope: str
    private_key_pem: str


TEST_OIN = Oin("00000099000000001000")
TEST_OIN_VALUE = TEST_OIN.value


@pytest.fixture
def oprf_test_router_context(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> OprfTestRouterContext:
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


def _blind_and_evaluate(
    client: TestClient,
    context: OprfTestRouterContext,
    headers: dict[str, str],
) -> tuple[str, str]:
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


def test_test_oprf_client_and_receiver_roundtrip(
    client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
) -> None:
    blind_factor, jwe_token = _blind_and_evaluate(
        client, oprf_test_router_context, valid_headers
    )

    receiver_response = client.post(
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
    assert body["jwe"]["headers"]["cty"] == "application/json"
    assert body["jws"] is None


def test_with_jwt_signing_oprf_eval_is_signed_and_test_routes_verify_it(
    client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
    jwt_signing: JwtSigningService,
) -> None:
    ctx = oprf_test_router_context
    blinded = client.post(
        "/test/oprf/client", json={"personalId": ctx.oprf_input}, headers=valid_headers
    ).json()
    eval_response = client.post(
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

    _, _, claims = decrypt_signed(jwe_token, ctx.private_key_pem, jwt_signing)
    assert claims["iss"] == JWT_ISSUER
    assert claims["subject"].startswith("pseudonym:eval:")

    receiver = client.post(
        "/test/oprf/receiver",
        json={
            "blind_factor": blinded["blind_factor"],
            "jwe": jwe_token,
            "priv_key_pem": ctx.private_key_pem,
        },
        headers=valid_headers,
    ).json()
    assert receiver["jwe"]["headers"]["cty"] == "JWT"
    assert receiver["jws"]["headers"]["kid"] == jwt_signing.active.kid
    assert receiver["jws"]["signature"] == "valid"
    assert receiver["jwe"]["decrypted"]["iss"] == JWT_ISSUER
    assert receiver["final_pseudonym"]

    decoded = client.post(
        "/test/jwe/decode",
        json={"jwe": jwe_token, "priv_key_pem": ctx.private_key_pem},
        headers=valid_headers,
    ).json()
    assert decoded["jws"]["signature"] == "valid"
    assert decoded["jwe"]["decrypted"]["subject"] == claims["subject"]


def test_test_oprf_receiver_incorrect_private_key(
    client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
) -> None:
    blind_factor, jwe_token = _blind_and_evaluate(
        client, oprf_test_router_context, valid_headers
    )
    other_private_key_pem, _ = generate_rsa_keypair()

    receiver_response = client.post(
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
    client: TestClient,
    valid_headers: dict[str, str],
) -> None:
    receiver_response = client.post(
        "/test/oprf/receiver",
        json={
            "blind_factor": "ZmFrZS1mYWN0b3I=",
            "jwe": "a.b.c.d.e",
            "priv_key_pem": "-----BEGIN PRIVATE KEY-----invalid",
        },
        headers=valid_headers,
    )
    assert receiver_response.status_code == 422
