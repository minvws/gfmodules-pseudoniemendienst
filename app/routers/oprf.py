import logging

import gfmodules.logging as gflog
from fastapi import APIRouter, Depends, Security
from jwcrypto import jwk
from starlette.responses import JSONResponse

from app import container
from app.auth import require_scopes
from app.logging.events import Log
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope
from app.models.requests import BlindRequest
from app.services.key_resolver import KeyResolver
from app.services.oprf.oprf_service import OprfService
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()

_ENDPOINT = "/oprf/eval"


@router.post(
    "/oprf/eval",
    summary="Evaluate OPRF blind and returns an encrypted JWE for the organization",
    tags=["OPRF Services"],
)
def post_eval(
    req: BlindRequest,
    auth: AuthContext = Security(
        require_scopes, scopes=[AuthorizationScope.OPRF.value]
    ),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
    org_service: OrgService = Depends(container.get_org_service),
    oprf_service: OprfService = Depends(container.get_oprf_service),
) -> JSONResponse:
    handelende_oin = str(auth.claims.client_organization_id)
    doel_oin = str(req.recipientOrganization)

    oin = req.recipientOrganization
    org = org_service.get_by_oin(oin)
    if org is None:
        gflog.emit(
            logger,
            Log.OPRF_REFUSED_NO_ACTIVE_PUBKEY,
            "OPRF refused: no organization found for target OIN",
            fields={
                "handelende_oin": handelende_oin,
                "doel_oin": doel_oin,
                "endpoint": _ENDPOINT,
            },
        )
        return JSONResponse(
            {"error": "No organization found for this OIN"}, status_code=404
        )
    key_entry = key_resolver.resolve_entry(org.id, req.recipientScope)
    if key_entry is None:
        gflog.emit(
            logger,
            Log.OPRF_REFUSED_NO_ACTIVE_PUBKEY,
            "OPRF refused: target organization has no active public key for scope",
            fields={
                "handelende_oin": handelende_oin,
                "doel_oin": doel_oin,
                "endpoint": _ENDPOINT,
            },
        )
        return JSONResponse(
            {"error": "No public key found for this organization and/or scope"},
            status_code=404,
        )
    pub_key_jwk = jwk.JWK.from_pem(key_entry.key_data.encode("ascii"))

    try:
        result = oprf_service.eval_blind(req, pub_key_jwk, key_entry.key_id)
    except ValueError as e:
        gflog.emit(
            logger,
            Log.OPRF_EVAL_FAILED,
            "OPRF evaluation failed",
            fields={
                "handelende_oin": handelende_oin,
                "doel_oin": doel_oin,
                "error_type": getattr(e, "error_type", "crypto_evaluation_failure"),
                "endpoint": _ENDPOINT,
            },
        )
        return JSONResponse({"error": "Unable to evaluate blind"}, status_code=400)

    gflog.emit(
        logger,
        Log.OPRF_EVAL_OK,
        "OPRF evaluation succeeded",
        fields={
            "handelende_oin": handelende_oin,
            "doel_oin": doel_oin,
            "oprf_secret_versie": max(result.key_versions),
            "ontvanger_pubkey_id": key_entry.key_id,
        },
    )
    return JSONResponse({"jwe": result.jwe})
