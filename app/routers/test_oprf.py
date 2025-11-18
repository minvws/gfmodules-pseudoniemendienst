import json
import logging

from cryptography import x509
from fastapi import APIRouter, Depends
from fastapi.encoders import jsonable_encoder
from jwcrypto import jwe, jwk
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import container
from app.models.requests import InputRequest, ReceiverRequest, JweReceiverRequest
from app.personal_id import PersonalId, PersonalIdJSONEncoder
from app.rid import RidUsage
from app.services.mtls_service import MtlsService
from app.services.oprf.oprf_service import OprfService
from app.services.pseudonym_service import PseudonymService

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
"""
)
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


@router.post(
    "/test/jwe/decode",
    summary="Decode a JWE with a specific private key",
    tags=["OPRF Testing Services"],
    description="""
This endpoint is for testing purposes only. It decodes a given JWE using the provided private key. It does not
check any mtls or organizational permissions.
"""
)
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


@router.post(
    "/test/pseudonym/reversible",
    summary="Reverse a pseudonym",
    tags=["OPRF Testing Services"],
    description="""
This endpoint is for testing purposes only. It reverses a reversible pseudonym. Note that this endpoint DOES check
if the calling organization is authorized to reverse pseudonyms (max_key_usage == BSN).
"""
)
def post_test_reversible_pseudonym(
    request: Request,
    pseudonym: str,
    pseudonym_service: PseudonymService = Depends(container.get_pseudonym_service),
    mtls_service: MtlsService = Depends(container.get_mtls_service),
) -> JSONResponse:
    # Check if we as an organization are allowed to reverse pseudonyms (max_key_usage == BSN)
    org = mtls_service.get_org_from_request(request)
    if org.max_rid_usage != RidUsage.Bsn:
        return JSONResponse({
            "error": "Organization is not authorized to reverse pseudonyms."
        }, status_code=403)

    parts = pseudonym.split(":")
    if len(parts) == 3 and parts[0] == "pseudonym" and parts[1] == "reversible":
        pseudonym = parts[2]
    else:
        return JSONResponse({
            "error": "Invalid pseudonym format. Expected format: pseudonym:reversible:<value>"
        }, status_code=400)

    try:
        decoded = pseudonym_service.decrypt_reversible_pseudonym(pseudonym, str(org.ura))
    except Exception as e:
        return JSONResponse({
            "error": f"Failed to reverse pseudonym: {str(e)}"
        }, status_code=400)

    return JSONResponse(content=jsonable_encoder({
        "pseudonym": pseudonym,
        "decoded": decoded,
    }, custom_encoder={PersonalId: lambda v: json.loads(json.dumps(v, cls=PersonalIdJSONEncoder))}))


@router.get(
    "/test/mtls",
    summary="Returns MTLS information about the calling organization",
    tags=["OPRF Testing Services"],
    description="""
This endpoint is for testing purposes only. It will return information about the organization
that called this endpoint using MTLS.
"""
)
def test_mtls(
    request: Request,
    mtls_service: MtlsService = Depends(container.get_mtls_service),
) -> JSONResponse:
    org = mtls_service.get_org_from_request(request)

    cert_pem = mtls_service.get_mtls_cert(request)
    cert = x509.load_pem_x509_certificate(cert_pem)

    ret = {
        "cert_pem": cert_pem,
        "cert": {
            'subject': str(cert.subject),
            'issuer': str(cert.issuer),
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
        },
        "uzi": mtls_service.get_mtls_uzi_data(request),
    }

    if org:
        ret["organization"] = {
            "name": org.name,
            "id": org.id,
            "max_rid_usage": org.max_rid_usage,
        }

    return JSONResponse(content=jsonable_encoder(ret))


