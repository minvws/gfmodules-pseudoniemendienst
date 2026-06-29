"""
End-to-end integration test for HSM key versioning.

It registers an organization with a public key, creates key versions through
the public ``/key-versions`` endpoint and verifies that an OPRF evaluation
returns a pseudonym carrying every active key version in the resulting JWE.

The HSM itself is mocked: ``requests.post`` returns a deterministic evaluation
per key version, so we can assert exactly which versions end up in the JWE.
"""

import base64
import json
from typing import Any
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jwcrypto import jwe as jwelib
from jwcrypto import jwk
from starlette.testclient import TestClient

from app import container
from app.config import ConfigOprf
from app.db.db import Database
from app.rid import RidUsage
from app.models.oin import Oin
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.key_resolver import KeyResolver
from app.services.oprf.oprf_service import OprfService
from app.services.org_service import OrgService

TEST_OIN = Oin("00000099000000001000")
RECIPIENT_ORG = f"oin:{TEST_OIN}"
SCOPE = "nvi"


def _generate_rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_key_pem, public_key_pem


def _fake_hsm_post(url: str, json: dict[str, Any], **kwargs: Any) -> MagicMock:
    """Return a distinct evaluation per key version, derived from the label."""

    # Return slot info when asked
    if url == "https://hsm.local/hsm/softhsm/SoftHSMLabel":
        resp = MagicMock()
        resp.json.return_value = {
            "objects": ["foobar"],
        }
        return resp

    version = json["label"].rsplit("v", 1)[-1]
    resp = MagicMock()
    resp.json.return_value = {
        "result": base64.b64encode(f"eval-v{version}".encode()).decode()
    }
    return resp


def _eval_v(version: str) -> str:
    """The expected (mocked) evaluation bytes for a version, base64url encoded."""
    return base64.urlsafe_b64encode(f"eval-v{version}".encode()).decode("utf-8")


def _decrypt_jwe(jwe_str: str, private_key_pem: str) -> dict[str, Any]:
    token = jwelib.JWE()
    token.deserialize(jwe_str)
    token.decrypt(jwk.JWK.from_pem(private_key_pem.encode("ascii")))
    return dict(json.loads(token.payload.decode("utf-8")))


def _eval(client: TestClient) -> Any:
    blinded = base64.urlsafe_b64encode(b"blinded").decode("ascii")
    return client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded,
            "recipientOrganization": RECIPIENT_ORG,
            "recipientScope": SCOPE,
        },
        headers={"x-gf-oin": str(TEST_OIN), "x-gf-audience": "prs.service"},
    )


def test_new_key_version_is_added_to_jwe(
    app: FastAPI,
    client: TestClient,
    database: Database,
    org_service: OrgService,
    key_resolver: KeyResolver,
) -> None:
    # 1. Register an organization with a public key.
    org = org_service.create(
        oin=TEST_OIN, name=f"Org {TEST_OIN}", max_key_usage=RidUsage.ReversiblePseudonym
    )
    private_key_pem, public_key_pem = _generate_rsa_keypair()
    key_resolver.create(org.id, [SCOPE], None, public_key_pem)

    # Route OPRF evaluation through a (mocked) HSM that reads its active key
    # versions from the same database the endpoint writes to.
    hsm_oprf = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
    )
    app.dependency_overrides[container.get_oprf_service] = lambda: hsm_oprf

    try:
        with patch(
            "app.services.oprf.oprf_service.requests.post", side_effect=_fake_hsm_post
        ):
            # 2. Create version 1 of the HSM key.
            resp = client.post(
                "/key-versions",
                json={"oin": str(TEST_OIN)},
                headers={"x-gf-oin": str(TEST_OIN), "x-gf-audience": "prs.service"},
            )
            assert resp.status_code == 201
            assert resp.json()["version"] == 1

            # 3. We get a pseudonym back, carrying only version 1.
            eval_resp = _eval(client)
            assert eval_resp.status_code == 200
            body = _decrypt_jwe(eval_resp.json()["jwe"], private_key_pem)
            assert body["aud"] == RECIPIENT_ORG
            assert body["scope"] == SCOPE
            assert body["subject"] == "pseudonym:eval:" + _eval_v("1")
            assert body["extra_versions"] == {}

            # 4. Create version 2 of the HSM key.
            resp = client.post(
                "/key-versions",
                json={"oin": str(TEST_OIN)},
                headers={"x-gf-oin": str(TEST_OIN), "x-gf-audience": "prs.service"},
            )
            assert resp.status_code == 201
            assert resp.json()["version"] == 2

            # 5. The JWE now carries version 2 as the subject (latest) and
            #    version 1 as an extra version.
            eval_resp = _eval(client)
            assert eval_resp.status_code == 200
            body = _decrypt_jwe(eval_resp.json()["jwe"], private_key_pem)
            assert body["subject"] == "pseudonym:eval:" + _eval_v("2")
            assert body["extra_versions"] == {"1": _eval_v("1")}
    finally:
        app.dependency_overrides.pop(container.get_oprf_service, None)
