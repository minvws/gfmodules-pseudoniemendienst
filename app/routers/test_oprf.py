import base64
import json
from typing import Annotated, Any

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import APIRouter, Depends
from jwcrypto import jwe, jwk, jws
from pydantic import BaseModel, Field, field_validator
from starlette.responses import JSONResponse

from app import container
from app.services.jwe_token import Jwe
from app.services.oprf.oprf_service import OprfService

router = APIRouter()


def _private_key_from_pem(pem: str) -> jwk.JWK:
    return jwk.JWK.from_pyca(load_pem_private_key(pem.encode(), password=None))


class JweReceiverRequest(BaseModel):
    jwe: str = Field(pattern=r"^[^.]*(\.[^.]*){4}$")
    priv_key_pem: str

    @field_validator("priv_key_pem")
    @classmethod
    def validate_priv_key_pem(cls, pem: str) -> str:
        _private_key_from_pem(pem)
        return pem


class ReceiverRequest(JweReceiverRequest):
    blind_factor: str


class InputRequest(BaseModel):
    personalId: str


def _b64url_json(part: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _verify_signature(token: str, kid: str, jwe_builder: Jwe) -> str:
    """Checks the inner JWS against this PRS's own signing keys."""
    if jwe_builder.signing is None:
        return "not checked: JWT signing is disabled"
    for public in jwe_builder.signing.public_jwks():
        if public["kid"] == kid:
            parsed = jws.JWS()
            parsed.deserialize(token)
            try:
                parsed.verify(jwk.JWK(**public), alg=public["alg"])
            except jws.InvalidJWSSignature:
                return "invalid"
            return "valid"
    return "unknown kid"


def _jwe_report(req: JweReceiverRequest, jwe_builder: Jwe) -> dict[str, Any]:
    """
    The JWE headers and claims, and for a nested JWT the inner JWS header and
    signature check.
    """
    priv_key = _private_key_from_pem(req.priv_key_pem)
    token = jwe.JWE.from_jose_token(req.jwe)
    inner: dict[str, Any] | None = None
    try:
        token.decrypt(priv_key)
        plaintext = token.payload.decode("utf-8")
        if token.jose_header.get("cty") == "JWT":
            header_part, payload_part, _ = plaintext.split(".")
            inner_headers = _b64url_json(header_part)
            decrypted = _b64url_json(payload_part)
            inner = {
                "headers": inner_headers,
                "signature": _verify_signature(
                    plaintext, inner_headers.get("kid", ""), jwe_builder
                ),
            }
        else:
            decrypted = json.loads(plaintext)
    except Exception as e:  # noqa: BLE001
        decrypted = f"Could not decrypt JWE: {e}"

    return {
        "jwe_data": req.jwe,
        "priv_key_pem": req.priv_key_pem,
        "priv_key_kid": priv_key.thumbprint(),
        "jwe": {
            "headers": token.jose_header,
            "decrypted": decrypted,
        },
        "jws": inner,
    }


@router.post(
    "/test/oprf/client",
    summary="Create a blinded input and factor for a given BSN (or any other input)",
    tags=["OPRF Testing Services"],
    description="""
This endpoint is for testing purposes only. It simulates the client-side OPRF
blinding process. Given a personal ID (e.g., BSN), it returns a blinded input
and the blind factor used for blinding.

The personalId is not validated. Because the Pseudoniemendienst is not able to read
the content of the blindedInput it does not validate the input.
""",
)
def post_test_client(
    req: InputRequest,
    oprf_service: Annotated[OprfService, Depends(container.get_oprf_service)],
) -> JSONResponse:
    return JSONResponse(oprf_service.blind_input(req.personalId))


@router.post(
    "/test/oprf/receiver",
    summary="Test receiver decryption of JWE with blind factor",
    tags=["OPRF Testing Services"],
    description="""
This endpoint is for testing purposes only. It simulates the server-side OPRF
finalization process. Given a JWE and a blind factor, it decrypts the JWE
using the provided private key and finalizes the pseudonym using the blind factor.

Note that the private key provided should starts with -----BEGIN PRIVATE KEY-----
and should be all on a single line.
""",
)
def post_test_receiver(
    req: ReceiverRequest,
    oprf_service: Annotated[OprfService, Depends(container.get_oprf_service)],
    jwe_builder: Annotated[Jwe, Depends(container.get_jwe)],
) -> JSONResponse:
    report = _jwe_report(req, jwe_builder)
    decrypted = report["jwe"]["decrypted"]

    subject = "unknown"
    pseudonym = "unknown"
    if isinstance(decrypted, dict):
        subject = decrypted.get("subject", "").split(":")[-1]
        try:
            pseudonym = oprf_service.finalize(req.blind_factor, subject)
        except Exception as e:  # noqa: BLE001
            pseudonym = f"Could not finalize pseudonym: {e}"

    return JSONResponse(
        {
            **report,
            "blind_factor": req.blind_factor,
            "eval_subject": subject,
            "final_pseudonym": pseudonym,
        }
    )


@router.post(
    "/test/jwe/decode",
    summary="Decode a JWE with a specific private key",
    tags=["OPRF Testing Services"],
    description="""
This endpoint is for testing purposes only. It decodes a given JWE using the provided private key. It does not
check any mtls or organizational permissions.
""",
)
def post_test_jwe_decode(
    req: JweReceiverRequest,
    jwe_builder: Annotated[Jwe, Depends(container.get_jwe)],
) -> JSONResponse:
    return JSONResponse(_jwe_report(req, jwe_builder))
