import base64
import json
from dataclasses import dataclass
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
import pyoprf
import pytest
from starlette.testclient import TestClient

from app.rid import RidUsage
from app.services.key_resolver import KeyResolver
from app.services.org_service import OrgService


@dataclass(frozen=True)
class OprfTestRouterContext:
    personal_identifier: Dict[str, str]
    recipient_organization: str
    recipient_scope: str
    private_key_pem: str


def generate_rsa_keypair() -> Tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return private_key_pem, public_key_pem


def setup_org_and_key(
    org_service: OrgService,
    key_resolver: KeyResolver,
    oin: str,
    scope: str,
) -> str:
    org = org_service.create(
        oin=oin,
        name=f"Integration OPRF Test Router Org {oin}",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )
    private_key_pem, public_key_pem = generate_rsa_keypair()
    key_resolver.create(org.id, [scope], None, public_key_pem)
    return private_key_pem


@pytest.fixture
def oprf_test_router_context(
    org_service: OrgService,
    key_resolver: KeyResolver,
) -> OprfTestRouterContext:
    recipient_organization = "oin:00000099000000001000"
    recipient_scope = "nvi"
    personal_identifier = {
        "landCode": "NL",
        "type": "bsn",
        "value": "950000012",
    }
    private_key_pem = setup_org_and_key(
        org_service=org_service,
        key_resolver=key_resolver,
        oin="00000099000000001000",
        scope=recipient_scope,
    )
    return OprfTestRouterContext(
        personal_identifier=personal_identifier,
        recipient_organization=recipient_organization,
        recipient_scope=recipient_scope,
        private_key_pem=private_key_pem,
    )


def test_test_oprf_client_and_receiver_roundtrip(
    client: TestClient,
    oprf_test_router_context: OprfTestRouterContext,
) -> None:
    client_response = client.post(
        "/test/oprf/client",
        json={"personalId": oprf_test_router_context.personal_identifier},
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
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
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
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
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
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
) -> None:
    info = (
        f"{oprf_test_router_context.recipient_organization}|"
        f"{oprf_test_router_context.recipient_scope}|v1"
    ).encode("utf-8")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    personal_id = json.dumps(
        oprf_test_router_context.personal_identifier,
        separators=(",", ":"),
    )
    derived_personal_id = hkdf.derive(personal_id.encode("utf-8"))

    _, blinded_input_raw = pyoprf.blind(derived_personal_id)
    blinded_input = base64.urlsafe_b64encode(blinded_input_raw).decode("ascii")

    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded_input,
            "recipientOrganization": oprf_test_router_context.recipient_organization,
            "recipientScope": oprf_test_router_context.recipient_scope,
        },
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )
    assert eval_response.status_code == 200

    receiver_response = client.post(
        "/test/oprf/receiver",
        json={
            "blind_factor": "ZmFrZS1mYWN0b3I=",
            "jwe": eval_response.json()["jwe"],
            "priv_key_pem": "-----BEGIN PRIVATE KEY-----invalid",
        },
        headers={"x-gf-oin": "00000099000000001000", "x-gf-audience": "prs.service"},
    )
    assert receiver_response.status_code == 200
    assert receiver_response.json()["jwe"]["decrypted"].startswith(
        "Could not decrypt JWE:"
    )
