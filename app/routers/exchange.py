import json
import logging
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app import container
from app.models.requests import ExchangeRequest, RidExchangeRequest, RidReceiveRequest
from app.personal_id import PersonalId
from app.rid import ALLOWED_BY_RID_USAGE, REQUIRED_MIN_USAGE, USAGE_RANK, RidUsage
from app.services.key_resolver import KeyResolver
from app.services.mtls_service import MtlsService
from app.services.oprf.jwe_token import BlindJwe
from app.services.org_service import OrgService
from app.services.pseudonym_service import PseudonymService, PseudonymType
from app.services.rid_service import RidService

logger = logging.getLogger(__name__)
router = APIRouter()

class OrganizationNotFound(HTTPException):
    def __init__(self, ura: str) -> None:
        super().__init__(status_code=404, detail=f"Organization with URA '{ura}' not found")

class InvalidRID(HTTPException):
    def __init__(self, message: str = "Invalid RID.") -> None:
        super().__init__(status_code=400, detail=message)

class InvalidURA(HTTPException):
    def __init__(self, ura: str) -> None:
        super().__init__(status_code=400, detail=f"Invalid organization URA '{ura}'. Must start with 'ura:'")

class PubKeyNotFound(HTTPException):
    def __init__(self, ura: str, scope: str) -> None:
        super().__init__(status_code=404, detail=f"No public key found for organization '{ura}' and scope '{scope}'")


@router.post("/receive", summary="Receive and decrypt RID", tags=["Exchange Services"])
def receive(
    req: RidReceiveRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    rid_service: RidService = Depends(container.get_rid_service),
    pseudonym_service: PseudonymService = Depends(container.get_pseudonym_service),
) -> Response:
    """
    Receive and decrypt a RID, validate it, and return a pseudonym of the requested type if allowed.
    """
    if not req.rid.startswith("rid:"):
        logger.error("received invalid RID: %s", req.rid)
        raise InvalidRID("Invalid RID. Should start with 'rid:'")
    rid = req.rid.removeprefix("rid:")

    try:
        plaintext = rid_service.decrypt_rid(rid)
        if not plaintext:
            logger.error("decrypted RID is empty")
            raise Exception("Empty plaintext")
    except Exception:
        logger.error("failed to decrypt RID: %s", rid, exc_info=True)
        raise InvalidRID("Failed to decrypt RID")

    try:
        payload: Dict[str, Any] = json.loads(plaintext)
    except json.JSONDecodeError:
        logger.error("failed to parse RID payload as JSON: %s", plaintext)
        raise InvalidRID(message="Malformed RID payload")

    recipient_org = payload.get("recipient_organization")
    recipient_scope = payload.get("recipient_scope")
    rid_usage = payload.get("usage")

    # Make sure the recipient org/scope matches what is in the RID
    if recipient_org != req.recipientOrganization or recipient_scope != req.recipientScope:
        logger.error("recipient organization/scope mismatch. Expected org: %s, scope: %s. Got org: %s, scope: %s",)
        raise InvalidRID(message="Invalid recipient organization and/or scope")

    # Make sure we have got the correct permissions to exchange the requested pseudonym type
    if rid_usage not in ALLOWED_BY_RID_USAGE:
        logger.error("unsupported RID usage: %s", rid_usage)
        raise InvalidRID(message="Unsupported RID usage")

    if req.pseudonymType not in ALLOWED_BY_RID_USAGE[rid_usage]:
        logger.error("requested pseudonym type '%s' not allowed by RID usage '%s'", req.pseudonymType, rid_usage)
        raise InvalidRID(message="Requested pseudonym type not allowed by RID usage")

    if not req.recipientOrganization.startswith("ura:"):
        logger.error("does not start with 'ura:': %s", req.recipientOrganization)
        raise InvalidURA(req.recipientOrganization)

    ura = req.recipientOrganization[4:]

    max_rid_usage = key_resolver.max_rid_usage(ura)
    if max_rid_usage is None:
        logger.error("no RID usage permissions found for organization: %s", ura)
        raise HTTPException(
            status_code=400,
            detail="Organization / scope is not allowed to exchange RIDs",
        )

    required = REQUIRED_MIN_USAGE.get(req.pseudonymType)
    if required is None:
        logger.error("unsupported pseudonym type requested: %s", req.pseudonymType)
        raise HTTPException(status_code=400, detail="Unsupported pseudonym type")

    if USAGE_RANK.get(max_rid_usage.name, 0) < USAGE_RANK[required]:
        logger.error("organization '%s' with max RID usage '%s' is not allowed to exchange pseudonym type '%s' which requires minimum RID usage '%s'", ura, max_rid_usage.name, req.pseudonymType, required)

        msg = {
            "bsn": "BSNs",
            "rp": "reversible pseudonyms or higher",
            "irp": "irreversible pseudonyms or higher",
        }[req.pseudonymType]
        raise HTTPException(
            status_code=400,
            detail=f"Organization / scope is not allowed to exchange {msg}",
        )

    try:
        pid = payload["personal_id"]
        if isinstance(pid, str):
            personal_id = PersonalId.from_str(pid)
        elif isinstance(pid, dict):
            personal_id = PersonalId.from_dict(pid)
        else:
            logger.error("invalid personal_id format in RID payload: %s", pid)
            raise InvalidRID(message="Invalid personal_id format in RID payload")
    except Exception:
        logger.error("failed to parse personal_id from RID payload: %s", payload.get("personal_id"), exc_info=True)
        raise InvalidRID(message="Invalid personal_id in RID payload")

    if req.pseudonymType == "bsn":
        value = personal_id.as_str()
    elif req.pseudonymType == "rp":
        res = pseudonym_service.generate_reversible_pseudonym(
            personal_id=personal_id,
            recipient_organization=payload["recipient_organization"] or "",
            recipient_scope=payload["recipient_scope"] or "",
        )
        value = "pseudonym:reversible:" + res
    else:
        res = pseudonym_service.generate_irreversible_pseudonym(
            personal_id=personal_id,
            recipient_organization=payload["recipient_organization"] or "",
            recipient_scope=payload["recipient_scope"] or "",
        )
        value = "pseudonym:irreversible:" + res

    return JSONResponse(content={"pseudonym": value, "type": req.pseudonymType})


@router.post("/exchange/rid", summary="Exchange RID", tags=["Exchange Services"])
def exchange_rid(
    req: RidExchangeRequest,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    rid_service: RidService = Depends(container.get_rid_service),
    org_service: OrgService = Depends(container.get_org_service),
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

    if not req.recipientOrganization.startswith("ura:"):
        raise InvalidURA(req.recipientOrganization)
    ura = req.recipientOrganization[4:]

    org = org_service.get_by_ura(ura)
    if org is None:
        raise OrganizationNotFound(ura)

    pub_key_jwk = key_resolver.resolve(org.id, req.recipientScope)
    if pub_key_jwk is None:
        logger.error("no public key found for organization '%s' and scope '%s'", ura, req.recipientScope)
        raise PubKeyNotFound(ura, req.recipientScope)

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

    return Response(status_code=201, content=jwe, headers={"Content-Type": "application/jwe"})

@router.post("/exchange/pseudonym", summary="Exchange pseudonym", tags=["Exchange Services"])
def exchange_pseudonym(
    req: ExchangeRequest,
    request: Request,
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    pseudonym_service: PseudonymService = Depends(container.get_pseudonym_service),
    org_service: OrgService = Depends(container.get_org_service),
    mtls_service: MtlsService = Depends(container.get_mtls_service),
) -> Response:
    if not req.recipientOrganization.startswith("ura:"):
        logger.error("URA does not start with 'ura:': %s", req.recipientOrganization)
        raise InvalidURA(req.recipientOrganization)
    recipient_organization = req.recipientOrganization[4:]

    org = org_service.get_by_ura(recipient_organization)
    if org is None:
        logger.error("recipient organization not found for URA: %s", recipient_organization)
        raise OrganizationNotFound(recipient_organization)

    if req.pseudonymType == PseudonymType.Irreversible:
        res = pseudonym_service.generate_irreversible_pseudonym(
            personal_id=req.personalId,
            recipient_organization=recipient_organization,
            recipient_scope=req.recipientScope,
        )
        subject = "pseudonym:irreversible:" + res
    elif req.pseudonymType == PseudonymType.Reversible:
        source_org = mtls_service.get_org_from_request(request)
        if source_org.max_rid_usage == RidUsage.IrreversiblePseudonym:
            logger.error("source organization '%s' is not allowed to exchange reversible pseudonyms due to insufficient RID usage permissions", source_org.ura)
            raise HTTPException(
                status_code=400,
                detail="Source organization is not allowed to exchange reversible pseudonyms.",
            )

        res = pseudonym_service.generate_reversible_pseudonym(
            personal_id=req.personalId,
            recipient_organization=recipient_organization,
            recipient_scope=req.recipientScope,
        )
        subject = "pseudonym:reversible:" + res
    else:
        logger.error("unsupported pseudonym type requested: %s", req.pseudonymType)
        raise HTTPException(status_code=400, detail="Unsupported pseudonym type")

    if subject is None:
        logger.error("pseudonym generation failed for personal_id: %s, recipient_organization: %s, recipient_scope: %s, pseudonym_type: %s", req.personalId.as_str(), recipient_organization, req.recipientScope, req.pseudonymType)
        raise HTTPException(status_code=500, detail="Pseudonym exchange failed")

    pub_key_jwk = key_resolver.resolve(org.id, req.recipientScope)
    if pub_key_jwk is None:
        logger.error("no public key found for organization '%s' and scope '%s'", recipient_organization, req.recipientScope)
        raise PubKeyNotFound(str(org.ura), req.recipientScope)

    jwe = BlindJwe.build(
        audience=recipient_organization,
        scope=req.recipientScope,
        subject=subject,
        pub_key=pub_key_jwk
    )

    return Response(status_code=201, content=jwe, headers={"Content-Type": "application/jwe"})

