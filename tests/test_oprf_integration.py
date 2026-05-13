import base64
import json
from dataclasses import dataclass
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwe, jwk
import pyoprf
import pytest
from starlette.testclient import TestClient

from app.rid import RidUsage
from app.services.key_resolver import KeyResolver
from app.services.org_service import OrgService


@dataclass(frozen=True)
class OprfIntegrationContext:
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
    ura: str,
    scope: str,
) -> str:
    org = org_service.create(
        ura=ura,
        name=f"Integration OPRF Org {ura}",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )
    private_key_pem, public_key_pem = generate_rsa_keypair()
    key_resolver.create(org.id, [scope], public_key_pem)

    return private_key_pem


def run_oprf_eval_and_unblind(
    client: TestClient,
    private_key_pem: str,
    personal_identifier: Dict[str, str],
    recipient_organization: str,
    recipient_scope: str,
) -> str:
    assert pyoprf is not None
    info = f"{recipient_organization}|{recipient_scope}|v1".encode("utf-8")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    personal_id = json.dumps(personal_identifier, separators=(",", ":"))
    derived_personal_id = hkdf.derive(personal_id.encode("utf-8"))

    blind_factor_raw, blinded_input_raw = pyoprf.blind(derived_personal_id)
    blind_factor = base64.urlsafe_b64encode(blind_factor_raw).decode("ascii")
    blinded_input = base64.urlsafe_b64encode(blinded_input_raw).decode("ascii")

    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded_input,
            "recipientOrganization": recipient_organization,
            "recipientScope": recipient_scope,
        },
    )
    assert eval_response.status_code == 200
    token = jwe.JWE()
    token.deserialize(eval_response.json()["jwe"])
    token.decrypt(jwk.JWK.from_pem(private_key_pem.encode("ascii")))

    body = json.loads(token.payload.decode("utf-8"))
    assert body["aud"] == recipient_organization
    assert body["scope"] == recipient_scope
    assert body["subject"].startswith("pseudonym:eval:")

    eval_subject = body["subject"].split(":")[-1]
    final = pyoprf.unblind(
        base64.urlsafe_b64decode(blind_factor),
        base64.urlsafe_b64decode(eval_subject),
    )
    final_pseudonym = base64.urlsafe_b64encode(final).decode("ascii")
    assert final_pseudonym

    return final_pseudonym


@pytest.fixture
def oprf_context(
    org_service: OrgService,
    key_resolver: KeyResolver,
) -> OprfIntegrationContext:
    recipient_organization = "ura:12345678"
    recipient_scope = "nvi"
    personal_identifier = {
        "landCode": "NL",
        "type": "bsn",
        "value": "950000012",
    }
    private_key_pem = setup_org_and_key(
        org_service=org_service,
        key_resolver=key_resolver,
        ura="12345678",
        scope=recipient_scope,
    )
    return OprfIntegrationContext(
        personal_identifier=personal_identifier,
        recipient_organization=recipient_organization,
        recipient_scope=recipient_scope,
        private_key_pem=private_key_pem,
    )


def test_oprf_integration_roundtrip_is_stable_for_same_input(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
) -> None:

    pseudonym_1 = run_oprf_eval_and_unblind(
        client=client,
        private_key_pem=oprf_context.private_key_pem,
        personal_identifier=oprf_context.personal_identifier,
        recipient_organization=oprf_context.recipient_organization,
        recipient_scope=oprf_context.recipient_scope,
    )
    pseudonym_2 = run_oprf_eval_and_unblind(
        client=client,
        private_key_pem=oprf_context.private_key_pem,
        personal_identifier=oprf_context.personal_identifier,
        recipient_organization=oprf_context.recipient_organization,
        recipient_scope=oprf_context.recipient_scope,
    )

    assert pseudonym_1 == pseudonym_2


def test_oprf_eval_invalid_scope_returns_not_found(
    client: TestClient,
    oprf_context: OprfIntegrationContext,
) -> None:
    assert pyoprf is not None
    info = (
        f"{oprf_context.recipient_organization}|{oprf_context.recipient_scope}|v1"
    ).encode("utf-8")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    personal_id = json.dumps(oprf_context.personal_identifier, separators=(",", ":"))
    derived_personal_id = hkdf.derive(personal_id.encode("utf-8"))

    _, blinded_input_raw = pyoprf.blind(derived_personal_id)
    blinded_input = base64.urlsafe_b64encode(blinded_input_raw).decode("ascii")

    eval_response = client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded_input,
            "recipientOrganization": oprf_context.recipient_organization,
            "recipientScope": "invalid-scope",
        },
    )

    assert eval_response.status_code == 404
    assert eval_response.json() == {
        "error": "No public key found for this organization and/or scope"
    }
