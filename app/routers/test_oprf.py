import json
import logging

from fastapi import APIRouter, Depends
from jwcrypto import jwe, jwk
from pydantic import BaseModel
from starlette.responses import JSONResponse

from app import container
from app.services.oprf.oprf_service import OprfService

logger = logging.getLogger(__name__)
router = APIRouter()

class InputRequest(BaseModel):
    personalId: str

class ReceiverRequest(BaseModel):
    blind_factor: str
    jwe: str
    priv_key_pem: str

class JweReceiverRequest(BaseModel):
    jwe: str
    priv_key_pem: str

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


@router.post("/test/oprf/client", summary="Create a blinded input and factor for a given BSN (or any other input)", tags=["test-oprf"])
def post_test_eval(
    req: InputRequest,
    oprf_service: OprfService = Depends(container.get_oprf_service),
) -> JSONResponse:

    res = oprf_service.blind_input(req.personalId)
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



