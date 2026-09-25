import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from jwcrypto import jwe, jwk
from starlette.responses import JSONResponse

from app import container
from app.models.requests import InputRequest, JweReceiverRequest, ReceiverRequest
from app.services.oprf.oprf_service import OprfService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/test/oprf/client",
    summary="Create a blinded input and factor for a given BSN (or any other input)",
    tags=["OPRF Testing Services"],
    description="""
This endpoint is for testing purposes only. It simulates the client-side OPRF
blinding process. Given a personal ID (e.g., BSN), it returns a blinded input
and the blind factor used for blinding.

It takes the form of:

```json
{
    "personalId": {
      "landCode": "NL",
      "type": "bsn",
      "value": "950000012"
    }
}
```

or as a string:

```json
{
    "personalId": "NL:bsn:950000012"
}
```
""",
)
def post_test_eval(
    req: InputRequest,
    oprf_service: Annotated[OprfService, Depends(container.get_oprf_service)],
) -> JSONResponse:

    res = oprf_service.blind_input(req.personalId.as_str())
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
) -> JSONResponse:

    token = jwe.JWE()
    token.deserialize(req.jwe)
    headers = token.jose_header

    priv_key_kid = "unknown"
    plain_data = "unknown"
    subject = "unknown"
    pseudonym = "unknown"
    try:
        priv_key = jwk.JWK.from_pem(req.priv_key_pem.encode("ascii"))
        priv_key_kid = priv_key.thumbprint().rstrip("=")
        token.decrypt(priv_key)
        plaintext = token.payload.decode("utf-8")
        plain_data = json.loads(plaintext)
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
) -> JSONResponse:

    token = jwe.JWE()
    token.deserialize(req.jwe)
    headers = token.jose_header

    priv_key_kid = "unknown"
    try:
        priv_key = jwk.JWK.from_pem(req.priv_key_pem.encode("ascii"))
        priv_key_kid = priv_key.thumbprint().rstrip("=")
        token.decrypt(priv_key)
        plaintext = token.payload.decode("utf-8")
        plain_data = json.loads(plaintext)
    except Exception as e:  # noqa: BLE001
        plain_data = "Could not decrypt JWE: " + str(e)

    res = {
        "jwe_data": req.jwe,
        "priv_key_pem": req.priv_key_pem,
        "priv_key_kid": priv_key_kid,
        "jwe": {
            "headers": headers,
            "decrypted": plain_data,
        },
    }

    return JSONResponse(res)
