from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from app import container
from app.services.jwe_token import Jwe

router = APIRouter()

JWKS_MAX_AGE_SECONDS = 15 * 60


@router.get(
    "/.well-known/jwks",
    summary="Public keys for verifying signed pseudonyms",
    description=(
        "Returns the JSON Web Key Set (RFC 7517) with the public keys the PRS "
        "signs pseudonym JWTs with. Every configured signing key is listed, "
        "including keys no longer active, so tokens signed before a rotation "
        "stay verifiable. Receivers select the key by the `kid` in the JWT "
        "header. Only mounted when `enable_jwt_signing` is set."
    ),
    tags=["Service Information"],
    responses={
        200: {
            "description": "The JWKS",
            "content": {
                "application/json": {
                    "example": {
                        "keys": [
                            {
                                "kty": "RSA",
                                "n": "...",
                                "e": "AQAB",
                                "kid": "8XnMgBBynigdp-ThfbpM_hIyitWL61KhaiZD_W5ib5w",
                                "alg": "PS256",
                                "use": "sig",
                            }
                        ]
                    }
                }
            },
        },
        404: {"description": "JWT signing is disabled"},
    },
)
def get_jwks(
    jwe: Annotated[Jwe, Depends(container.get_jwe)],
) -> JSONResponse:
    if jwe.signing is None:
        raise HTTPException(status_code=404)
    return JSONResponse(
        {"keys": jwe.signing.public_jwks()},
        headers={"Cache-Control": f"public, max-age={JWKS_MAX_AGE_SECONDS}"},
    )
