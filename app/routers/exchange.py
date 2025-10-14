import json
import logging
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from starlette.responses import JSONResponse, Response

from app import container
from app.models.requests import ExchangeRequest, RidExchangeRequest, RidReceiveRequest
from app.rid import ALLOWED_BY_RID_USAGE, REQUIRED_MIN_USAGE, USAGE_RANK
from app.services.key_resolver import KeyResolver
from app.services.oprf.jwe_token import BlindJwe
from app.services.pseudonym_service import PseudonymService, PseudonymType
from app.services.tmp_rid_service import TmpRidService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/receive", summary="Receive and decrypt RID")
def receive(
    req: RidReceiveRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    rid_service: TmpRidService = Depends(container.get_tmp_rid_service),
) -> Response:
    """
    Receive and decrypt a RID, validate it, and return a pseudonym of the requested type if allowed.
    """
    if not req.rid.startswith("rid:"):
        raise HTTPException(status_code=400, detail="Invalid RID format")
    rid = req.rid.removeprefix("rid:")

    try:
        plaintext = rid_service.decrypt_rid(rid)
        if not plaintext:
            raise Exception("Empty plaintext")
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decrypt RID")


    try:
        payload: Dict[str, Any] = json.loads(plaintext)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Malformed RID payload")

    recipient_org = payload.get("recipient_organization")
    recipient_scope = payload.get("recipient_scope")
    rid_usage = payload.get("usage")

    # Make sure the recipient org/scope matches what is in the RID
    if recipient_org != req.recipientOrganization or recipient_scope != req.recipientScope:
        raise HTTPException(
            status_code=400,
            detail="RID not intended for this organization and/or scope",
        )

    # Make sure we have got the correct permissions to exchange the requested pseudonym type
    if rid_usage not in ALLOWED_BY_RID_USAGE:
        raise HTTPException(status_code=400, detail="Unsupported RID usage")

    if req.pseudonymType not in ALLOWED_BY_RID_USAGE[rid_usage]:
        raise HTTPException(
            status_code=400,
            detail="Requested pseudonym type not allowed for this RID",
        )

    max_rid_usage = key_resolver.max_rid_usage(req.recipientOrganization, req.recipientScope)
    if max_rid_usage is None:
        raise HTTPException(
            status_code=400,
            detail="Organization / scope is not allowed to exchange RIDs",
        )

    required = REQUIRED_MIN_USAGE.get(req.pseudonymType)
    if required is None:
        raise HTTPException(status_code=400, detail="Unsupported pseudonym type")

    if USAGE_RANK.get(max_rid_usage.name, 0) < USAGE_RANK[required]:
        msg = {
            "bsn": "BSNs",
            "rp": "reversible pseudonyms or higher",
            "irp": "irreversible pseudonyms or higher",
        }[req.pseudonymType]
        raise HTTPException(
            status_code=400,
            detail=f"Organization / scope is not allowed to exchange {msg}",
        )

    # TODO: Here we would generate the actual pseudonyms
    if req.pseudonymType == "bsn":
        value = "bsn:foobar"
    elif req.pseudonymType == "rp":
        value = "pseudonym:reversible:foobar"
    else:
        value = "pseudonym:irreversible:foobar"

    return JSONResponse(content={"pseudonym": value, "type": req.pseudonymType})


@router.post("/exchange/rid", summary="Exchange RID")
def exchange_rid(
    req: RidExchangeRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    rid_service: TmpRidService = Depends(container.get_tmp_rid_service),
) -> Response:
    """
    Exchange a personal ID for a RID that can be used by the recipient organization/scope
    """

    rid_data = {
        "usage": str(req.ridUsage),         # Maximum usage allowed for this RID (capped by the recipient org/scope)
        "recipient_organization": req.recipientOrganization,
        "recipient_scope": req.recipientScope,
        "personal_id": req.personalId.as_str(),
    }
    rid_str = json.dumps(rid_data)
    rid = rid_service.encrypt_rid(rid_str)

    pub_key_jwk = key_resolver.resolve(req.recipientOrganization, req.recipientScope)
    if pub_key_jwk is None:
        return JSONResponse({"error": "No public key found for this organization and/or scope"}, status_code=404)

    # Create a blind JWE token containing the RID
    jwe = BlindJwe.build(
        audience=req.recipientOrganization,
        scope=req.recipientScope,
        subject=f"rid:{rid}",
        pub_key=pub_key_jwk,
        extra_claims={
            "ridUsage": rid_data['usage'],
        }
    )

    return Response(status_code=201, content=jwe, headers={"Content-Type": "Multipart/Encrypted"})


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
        subject = "pseudonym:irreversible:" + res
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

