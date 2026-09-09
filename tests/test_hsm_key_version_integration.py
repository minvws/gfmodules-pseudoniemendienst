"""
End-to-end integration test for HSM key versioning.

It registers an organization with a public key, creates key versions through
the public ``/administration/key-versions`` endpoint and verifies that an OPRF evaluation
returns a pseudonym carrying every active key version in the resulting JWE.

The HSM itself is mocked: ``requests.post`` returns a deterministic evaluation
per key version, so we can assert exactly which versions end up in the JWE.
"""

import base64
import json
from typing import Any
from unittest.mock import MagicMock, patch

from conftest import generate_rsa_keypair
from fastapi import FastAPI
from jwcrypto import jwe as jwelib
from jwcrypto import jwk
from jwcrypto.jwk import JWK
from starlette.testclient import TestClient

from app import container
from app.config import ConfigOprf
from app.db.db import Database
from app.db.models import OrganizationEntity, OrganizationPublicKeyEntity
from app.db.session import DbSession
from app.models.oin import Oin
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.oprf.evaluators import HsmOprfEvaluator
from app.services.oprf.oprf_service import OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService

SCOPE = "nvi"


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


def _eval(client: TestClient, recipient_id: Oin, valid_headers: dict[str, str]) -> Any:
    blinded = base64.urlsafe_b64encode(b"blinded").decode("ascii")
    return client.post(
        "/oprf/eval",
        json={
            "encryptedPersonalId": blinded,
            "recipientOrganization": "oin:" + recipient_id.value,
            "recipientScope": SCOPE,
        },
        headers=valid_headers,
    )


def test_new_key_version_is_added_to_jwe(
    app: FastAPI,
    client: TestClient,
    database: Database,
    valid_headers: dict[str, str],
    persisted_organization: OrganizationEntity,
    persisted_organization_2: OrganizationEntity,
    db_session: DbSession,
) -> None:
    private_key, public_key = generate_rsa_keypair()
    pub_jwk = JWK.from_pem(public_key.encode())

    persisted_organization_2.public_keys.append(
        OrganizationPublicKeyEntity(domains=["*"], jwk=pub_jwk.export(as_dict=True))
    )
    db_session.commit()
    # Route OPRF evaluation through a (mocked) HSM that reads its active key
    # versions from the same database the endpoint writes to.
    hsm_oprf = OprfService(
        evaluator=HsmOprfEvaluator(
            hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
            hsm_key_version_service=HsmKeyVersionService(database),
        )
    )
    app.dependency_overrides[container.get_oprf_service] = lambda: hsm_oprf
    try:
        with patch(
            "app.services.oprf.evaluators.requests.post", side_effect=_fake_hsm_post
        ):
            # We get a pseudonym back, carrying only version 1.
            eval_resp = _eval(
                client, persisted_organization_2.external_id, valid_headers
            )
            assert eval_resp.status_code == 200
            body = _decrypt_jwe(eval_resp.json()["jwe"], private_key)
            assert body["aud"] == "oin:" + persisted_organization_2.external_id.value
            assert body["scope"] == SCOPE
            assert body["subject"] == "pseudonym:eval:" + _eval_v("1")
            assert body["extra_versions"] == {}

            # Create version 2 of the HSM key.
            resp = client.post(
                "/administration/key-versions",
                headers={
                    **valid_headers,
                    "x-gf-sub": persisted_organization_2.external_id.value,
                },
            )
            assert resp.status_code == 201
            assert resp.json()["version"] == 2

            # The JWE now carries version 2 as the subject (latest) and
            #    version 1 as an extra version.
            eval_resp = _eval(
                client, persisted_organization_2.external_id, valid_headers
            )
            assert eval_resp.status_code == 200
            body = _decrypt_jwe(eval_resp.json()["jwe"], private_key)
            assert body["subject"] == "pseudonym:eval:" + _eval_v("2")
            assert body["extra_versions"] == {"1": _eval_v("1")}
    finally:
        app.dependency_overrides.pop(container.get_oprf_service, None)
