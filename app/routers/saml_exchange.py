import logging
from typing import Any

from fastapi import APIRouter, Body, Depends
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

from app.auth import require_scope
from app.logging.events import SAML_EXCHANGE_OK, log_event
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope

logger = logging.getLogger(__name__)
router = APIRouter()

_ENDPOINT = "/saml-exchange/reversible-pseudonym"


@router.post(
    _ENDPOINT,
    summary="MOCK: exchange a DigiD SAML response for a reversible pseudonym",
    tags=["SAML Exchange Services"],
    description="""
It accepts any JSON body and returns that body unchanged. No SAML decryption
or validation is performed, and no pseudonym is derived.

Requires the `prs:saml-reversible-pseudonym` OAuth scope; the token itself is
validated upstream by the OIN-verifier proxy, which forwards its scopes in the
`x-gf-scope` header.
""",
)
def post_reversible_pseudonym(
    payload: Any = Body(...),
    auth: AuthContext = Depends(
        require_scope(AuthorizationScope.SAML_REVERSIBLE_PSEUDONYM)
    ),
) -> JSONResponse:
    handelende_oin = str(auth.claims.client_organization_id)

    log_event(
        logger,
        SAML_EXCHANGE_OK,
        "SAML exchange succeeded (mock: request echoed)",
        handelende_oin=handelende_oin,
    )
    return JSONResponse(jsonable_encoder(payload))
