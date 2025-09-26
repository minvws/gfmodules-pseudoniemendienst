import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from starlette.responses import JSONResponse, Response

from app import container
from app.services.key_resolver import KeyResolver
from app.services.oprf.jwe_token import BlindJwe
from app.services.pseudonym_service import PseudonymService

logger = logging.getLogger(__name__)
router = APIRouter()

class ExchangeRequest(BaseModel):
    personalId: str
    recipientOrganization: str
    recipientScope: str
    pseudonymType: Literal["irreversible"]

@router.post("/exchange/pseudonym", summary="Exchange pseudonym")
def exchange_pseudonym(
    req: ExchangeRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    pseudonym_service: PseudonymService = Depends(container.get_pseudonym_service),
) -> Response:
    if req.pseudonymType == "irreversible":
        res = pseudonym_service.exchange_irreversible_pseudonym(
            personal_id=req.personalId,
            recipient_organization=req.recipientOrganization,
            recipient_scope=req.recipientScope,
        )
        subject = "pseudonym:" + res
    else:
        raise HTTPException(status_code=400, detail="Unsupported pseudonym type")

    if subject is None:
        raise HTTPException(status_code=500, detail="Pseudonym exchange failed")


    pub_key_jwk = key_resolver.resolve(req.recipientOrganization, req.recipientScope)
    if pub_key_jwk is None:
        return JSONResponse({"error": "No public key found for this organization"}, status_code=404)

    jwe = BlindJwe.build(
        audience=req.recipientOrganization,
        scope=req.recipientScope,
        subject=subject,
        pub_key=pub_key_jwk
    )

    return Response(status_code=201, content=jwe, headers={"Content-Type": "Multipart/Encrypted"})

