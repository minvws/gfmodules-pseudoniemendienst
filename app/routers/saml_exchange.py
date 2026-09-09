import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, Security
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

from app import container
from app.auth import require_scopes
from app.logging.events import SAML_EXCHANGE_FAILED, SAML_EXCHANGE_OK, log_event
from app.models.auth.context import AuthContext
from app.models.auth.data import AuthorizationScope
from app.services.saml.client import SamlServiceClient, SamlServiceError

logger = logging.getLogger(__name__)
router = APIRouter()

_ENDPOINT = "/saml-exchange/reversible-pseudonym"


@router.post(
    _ENDPOINT,
    summary="MOCK: exchange a DigiD SAML response for a reversible pseudonym",
    tags=["SAML Exchange Services"],
    description="""
**This endpoint is a mock.** The payload is forwarded to the internal PRS-SAML
service (the SAML-ontvanger), which currently echoes it back unchanged; no SAML
decryption or validation is performed, and no pseudonym is derived.

Requires the `prs:saml-reversible-pseudonym` OAuth scope; the token itself is
validated upstream by the OIN-verifier proxy, which forwards its scopes in the
`x-gf-scope` header.
""",
)
def post_reversible_pseudonym(
    payload: Any = Body(...),
    auth: AuthContext = Security(
        require_scopes,
        scopes=[AuthorizationScope.SAML_REVERSIBLE_PSEUDONYM.value],
    ),
    saml_client: SamlServiceClient = Depends(container.get_saml_service_client),
) -> JSONResponse:
    handelende_oin = str(auth.claims.client_organization_id)

    try:
        result = saml_client.decrypt(payload)
    except SamlServiceError as e:
        log_event(
            logger,
            SAML_EXCHANGE_FAILED,
            "SAML exchange failed: PRS-SAML service error",
            handelende_oin=handelende_oin,
            error_type=e.error_type,
            endpoint=_ENDPOINT,
        )
        return JSONResponse({"error": "SAML exchange failed"}, status_code=502)

    log_event(
        logger,
        SAML_EXCHANGE_OK,
        "SAML exchange succeeded (mock: request echoed via PRS-SAML)",
        handelende_oin=handelende_oin,
    )
    return JSONResponse(jsonable_encoder(result))
