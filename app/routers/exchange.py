import logging
from fastapi import APIRouter, Depends, HTTPException
from starlette.responses import JSONResponse, Response

from app import container
from app.models.requests import ExchangeRequest
from app.services.key_resolver import KeyResolver
from app.services.oprf.jwe_token import BlindJwe
from app.services.pseudonym_service import PseudonymService, PseudonymType

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/exchange/pseudonym", summary="Exchange pseudonym")
def exchange_pseudonym(
    req: ExchangeRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    pseudonym_service: PseudonymService = Depends(container.get_pseudonym_service),
) -> Response:
    if req.pseudonymType == PseudonymType.Irreversible:
        res = pseudonym_service.exchange_irreversible_pseudonym(
            personal_id=req.personalId,
            recipient_organization=req.recipientOrganization,
            recipient_scope=req.recipientScope,
        )
        subject = "pseudonym:irreverible:" + res
    elif req.pseudonymType == PseudonymType.Reversible:
        res = pseudonym_service.exchange_reversible_pseudonym(
            personal_id=req.personalId,
            recipient_organization=req.recipientOrganization,
            recipient_scope=req.recipientScope,
        )
        subject = "pseudonym:reversible:" + res
    else:
        raise HTTPException(status_code=400, detail="Unsupported pseudonym type")

    if subject is None:
        raise HTTPException(status_code=500, detail="Pseudonym exchange failed")

    pub_key_jwk = key_resolver.resolve(req.recipientOrganization, req.recipientScope)
    if pub_key_jwk is None:
        return JSONResponse({"error": "No public key found for this organization and/or scope"}, status_code=404)

    jwe = BlindJwe.build(
        audience=req.recipientOrganization,
        scope=req.recipientScope,
        subject=subject,
        pub_key=pub_key_jwk
    )

    return Response(status_code=201, content=jwe, headers={"Content-Type": "Multipart/Encrypted"})

