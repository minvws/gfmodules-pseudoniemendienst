import base64
import json
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from jwcrypto import jwe, jwk, jws
from pydantic import BaseModel
from starlette.responses import JSONResponse

from app import container
from app.models.requests import JweReceiverRequest, ReceiverRequest
from app.services.jwe_token import Jwe
from app.services.oprf.oprf_service import OprfService

logger = logging.getLogger(__name__)
router = APIRouter()


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


def _decrypt_jwe(
    jwe_token: str, priv_key_pem: str, jwe_builder: Jwe
) -> tuple[dict[str, Any], str, Any, dict[str, Any] | None]:
    """
    Returns the JWE headers, the private key thumbprint, the claims, and for a
    nested JWT the inner JWS header and signature check.
    """
    token = jwe.JWE()
    token.deserialize(jwe_token)
    headers = token.jose_header

    priv_key_kid = "unknown"
    plain_data: Any = "unknown"
    inner: dict[str, Any] | None = None
    try:
        priv_key = jwk.JWK.from_pem(priv_key_pem.encode("ascii"))
        priv_key_kid = priv_key.thumbprint().rstrip("=")
        token.decrypt(priv_key)
        plaintext = token.payload.decode("utf-8")
        if headers.get("cty") == "JWT":
            header_part, payload_part, _ = plaintext.split(".")
            inner_headers = _b64url_json(header_part)
            plain_data = _b64url_json(payload_part)
            inner = {
                "headers": inner_headers,
                "signature": _verify_signature(
                    plaintext, inner_headers.get("kid", ""), jwe_builder
                ),
            }
        else:
            plain_data = json.loads(plaintext)
    except Exception as e:  # noqa: BLE001
        plain_data = "Could not decrypt JWE: " + str(e)

    return headers, priv_key_kid, plain_data, inner


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
def post_test_eval(
    req: InputRequest,
    oprf_service: Annotated[OprfService, Depends(container.get_oprf_service)],
) -> JSONResponse:

    res = oprf_service.blind_input(req.personalId)
    return JSONResponse(
        {
            "blinded_input": res["blinded_input"],
            "blind_factor": res["blind_factor"],
        }
    )


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
    headers, priv_key_kid, plain_data, inner = _decrypt_jwe(
        req.jwe, req.priv_key_pem, jwe_builder
    )

    subject = "unknown"
    pseudonym = "unknown"
    if isinstance(plain_data, dict):
        try:
            subject = plain_data.get("subject", "").split(":")[-1]
            pseudonym = oprf_service.finalize(req.blind_factor, subject)
        except Exception as e:  # noqa: BLE001
            plain_data = "Could not decrypt JWE: " + str(e)

    res = {
        "jwe_data": req.jwe,
        "priv_key_pem": req.priv_key_pem,
        "priv_key_kid": priv_key_kid,
        "blind_factor": req.blind_factor,
        "jwe": {
            "headers": headers,
            "decrypted": plain_data,
        },
        "jws": inner,
        "eval_subject": subject,
        "final_pseudonym": pseudonym,
    }

    return JSONResponse(res)


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
    headers, priv_key_kid, plain_data, inner = _decrypt_jwe(
        req.jwe, req.priv_key_pem, jwe_builder
    )

    res = {
        "jwe_data": req.jwe,
        "priv_key_pem": req.priv_key_pem,
        "priv_key_kid": priv_key_kid,
        "jwe": {
            "headers": headers,
            "decrypted": plain_data,
        },
        "jws": inner,
    }

    return JSONResponse(res)
