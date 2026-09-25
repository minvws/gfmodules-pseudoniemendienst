import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette.responses import JSONResponse

from app import container
from app.auth import get_auth_ctx
from app.models.auth.context import AuthContext
from app.models.organization_public_key import (
    OrganizationPublicKeyRequest,
)
from app.services.organization_public_key_service import OrganizationPublicKeyService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/keys",
    summary="Register decryption key with JWS",
    tags=["Key Registration Services"],
)
def post_key(
    req: OrganizationPublicKeyRequest,
    auth_ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
    organization_public_key_service: Annotated[
        OrganizationPublicKeyService,
        Depends(container.get_organization_public_key_service),
    ],
) -> JSONResponse:
    created_key = organization_public_key_service.create(
        auth_ctx.claims.organization_id,
        req.domains,
        req.jws,
    )

    return JSONResponse(status_code=201, content=created_key)


@router.get(
    "/keys",
    summary="List public key information for the authorized organization",
    tags=["Key Registration Services"],
)
def list_keys_for_org(
    auth_ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
    organization_public_key_service: Annotated[
        OrganizationPublicKeyService,
        Depends(container.get_organization_public_key_service),
    ],
) -> JSONResponse:
    entries = organization_public_key_service.get_by_org(
        auth_ctx.claims.organization_id
    )

    return JSONResponse(status_code=200, content=entries)


@router.put(
    "/keys/{id}",
    summary="Update a key for the authorized organization",
    tags=["Key Registration Services"],
)
def put_key(
    id: Annotated[UUID, Path(title="The ID of the key to update")],
    req: OrganizationPublicKeyRequest,
    auth_ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
    organization_public_key_service: Annotated[
        OrganizationPublicKeyService,
        Depends(container.get_organization_public_key_service),
    ],
) -> JSONResponse:
    updated = organization_public_key_service.update(
        id,
        auth_ctx.claims.organization_id,
        req.domains,
        req.jws,
    )

    return JSONResponse(status_code=200, content=updated)


@router.delete(
    "/keys/{id}",
    summary="Delete a key for the authorized organization",
    tags=["Key Registration Services"],
)
def delete_key(
    id: Annotated[UUID, Path(title="The ID of the key to delete")],
    auth_ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
    organization_public_key_service: Annotated[
        OrganizationPublicKeyService,
        Depends(container.get_organization_public_key_service),
    ],
) -> JSONResponse:
    deleted = organization_public_key_service.delete(
        id, auth_ctx.claims.organization_id
    )
    if not deleted:
        logger.warning(
            "key %s for organization %s was not deleted",
            id,
            auth_ctx.claims.organization_id,
        )
        raise HTTPException(status_code=403, detail="forbidden")

    logger.info("key with id %s deleted successfully", id)
    return JSONResponse(status_code=200, content={"message": "key deleted"})
