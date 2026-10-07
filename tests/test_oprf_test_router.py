import base64
from dataclasses import dataclass

import pyoprf
import pytest
from conftest import setup_org_and_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.testclient import TestClient

from app.db.models import OrganizationEntity
from app.models.oin import Oin
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


def test_test_oprf_client_and_receiver_roundtrip(
    client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
) -> None:
    client_response = client.post(
        "/test/oprf/client",
        json={"personalId": oprf_test_router_context.oprf_input},
        headers=valid_headers,
    )
    assert client_response.status_code == 200

    blinded_input = client_response.json()["blinded_input"]
    blind_factor = client_response.json()["blind_factor"]
    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded_input,
            "recipientOrganization": oprf_test_router_context.recipient_organization,
            "recipientScope": oprf_test_router_context.recipient_scope,
        },
        headers=valid_headers,
    )
    assert eval_response.status_code == 200
    jwe_token = eval_response.json()["jwe"]

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


def test_test_oprf_receiver_invalid_private_key(
    client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
    valid_headers: dict[str, str],
) -> None:
    info = (
        f"{oprf_test_router_context.recipient_organization}|"
        f"{oprf_test_router_context.recipient_scope}|v1"
    ).encode()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    oprf_input = oprf_test_router_context.oprf_input
    derived_personal_id = hkdf.derive(oprf_input.encode("utf-8"))

    _, blinded_input_raw = pyoprf.blind(derived_personal_id)
    blinded_input = base64.urlsafe_b64encode(blinded_input_raw).decode("ascii")

    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded_input,
            "recipientOrganization": oprf_test_router_context.recipient_organization,
            "recipientScope": oprf_test_router_context.recipient_scope,
        },
        headers=valid_headers,
    )
    assert eval_response.status_code == 200

    receiver_response = client.post(
        "/test/oprf/receiver",
        json={
            "blind_factor": "ZmFrZS1mYWN0b3I=",
            "jwe": eval_response.json()["jwe"],
            "priv_key_pem": "-----BEGIN PRIVATE KEY-----invalid",
        },
        headers=valid_headers,
    )
    assert receiver_response.status_code == 200
    assert receiver_response.json()["jwe"]["decrypted"].startswith(
        "Could not decrypt JWE:"
    )
