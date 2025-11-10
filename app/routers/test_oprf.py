import json
import logging

from fastapi import APIRouter, Depends
from fastapi.encoders import jsonable_encoder
from jwcrypto import jwe, jwk
from starlette.responses import JSONResponse

from app import container
from app.models.requests import InputRequest, ReceiverRequest, JweReceiverRequest
from app.personal_id import PersonalId, PersonalIdJSONEncoder
from app.services.oprf.oprf_service import OprfService
from app.services.pseudonym_service import PseudonymService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/test/oprf/gen_rsa_key", summary="Create a RSA (1024bit) key for test usage.", tags=["test-oprf"])
def post_gen_rsa_key() -> JSONResponse:
    key = jwk.JWK.generate(kty='RSA', size=1024)
    priv_pem = key.export_to_pem(private_key=True, password=None).decode('ascii')
    pub_pem = key.export_to_pem(private_key=False, password=None).decode('ascii')

    return JSONResponse({
        "private_key_pem": priv_pem,
        "public_key_pem": pub_pem,
        "public_key_kid": key.thumbprint().rstrip("="),
    })


@router.post(
    "/test/oprf/client",
    summary="Create a blinded input and factor for a given BSN (or any other input)",
    tags=["test-oprf"],
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
```

or as a string:

```json
{
    "personalId": "NL:bsn:950000012"
}
```
"""
)
def post_test_eval(
    req: InputRequest,
    oprf_service: OprfService = Depends(container.get_oprf_service),
) -> JSONResponse:

    res = oprf_service.blind_input(req.personalId.as_str())
    return JSONResponse({
        "blinded_input": res['blinded_input'],
        "blind_factor": res['blind_factor'],
    })


@router.post("/test/oprf/receiver", summary="Test receiver decryption of JWE with blind factor", tags=["test-oprf"])
def post_test_receiver(
    req: ReceiverRequest,
    oprf_service: OprfService = Depends(container.get_oprf_service),
) -> JSONResponse:

    token = jwe.JWE()
    token.deserialize(req.jwe)
    headers = token.jose_header

    priv_key_kid = "unknown"
    plain_data = "unknown"
    subject = "unknown"
    pseudonym = "unknown"
    try:
        priv_key = jwk.JWK.from_pem(req.priv_key_pem.encode('ascii'))
        priv_key_kid = priv_key.thumbprint().rstrip("=")
        token.decrypt(priv_key)
        plaintext = token.payload.decode('utf-8')
        plain_data = json.loads(plaintext)
        subject = plain_data.get("subject", "").split(":")[-1]
        pseudonym = oprf_service.finalize(req.blind_factor, subject)
    except Exception as e:
        plain_data = "Could not decrypt JWE: " + str(e)


    res = {
        'jwe_data': req.jwe,
        'priv_key_pem': req.priv_key_pem,
        'priv_key_kid': priv_key_kid,
        'blind_factor': req.blind_factor,
        'jwe': {
            'headers': headers,
            'decrypted': plain_data,
        },
        'eval_subject': subject,
        'final_pseudonym': pseudonym,
    }

    return JSONResponse(res)


@router.post("/test/jwe/decode", summary="Decode a JWE with a specific private key", tags=["test-oprf"])
def post_test_jwe_decode(
    req: JweReceiverRequest,
) -> JSONResponse:

    token = jwe.JWE()
    token.deserialize(req.jwe)
    headers = token.jose_header

    priv_key_kid = "unknown"
    try:
        priv_key = jwk.JWK.from_pem(req.priv_key_pem.encode('ascii'))
        priv_key_kid = priv_key.thumbprint().rstrip("=")
        token.decrypt(priv_key)
        plaintext = token.payload.decode('utf-8')
        plain_data = json.loads(plaintext)
    except Exception as e:
        plain_data = "Could not decrypt JWE: " + str(e)


    res = {
        'jwe_data': req.jwe,
        'priv_key_pem': req.priv_key_pem,
        'priv_key_kid': priv_key_kid,
        'jwe': {
            'headers': headers,
            'decrypted': plain_data,
        },
    }

    return JSONResponse(res)


@router.post("/test/pseudonym/reversible", summary="Reverse a pseudonym", tags=["test-oprf"])
def post_test_reversible_pseudonym(
    pseudonym: str,
    pseudonym_service: PseudonymService = Depends(container.get_pseudonym_service),
) -> JSONResponse:
    parts = pseudonym.split(":")
    if len(parts) == 3 and parts[0] == "pseudonym" and parts[1] == "reversible":
        pseudonym = parts[2]
    else:
        return JSONResponse({
            "error": "Invalid pseudonym format. Expected format: pseudonym:reversible:<value>"
        }, status_code=400)

    try:
        decoded = pseudonym_service.decode_reversible_pseudonym(pseudonym)
    except Exception as e:
        return JSONResponse({
            "error": f"Failed to reverse pseudonym: {str(e)}"
        }, status_code=400)


    return JSONResponse(content=jsonable_encoder({
        "pseudonym": pseudonym,
        "decoded": decoded,
    }, custom_encoder={PersonalId: lambda v: json.loads(json.dumps(v, cls=PersonalIdJSONEncoder))}))


