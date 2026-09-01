import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

from app import container
from app.auth import get_auth_ctx
from app.models.auth.context import AuthContext
from app.models.requests import HsmKeyVersionRequest, HsmKeyVersionUpdateRequest
from app.services.hsm_key_version_service import (
    HsmKeyVersionNotFoundError,
    HsmKeyVersionService,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/key-versions",
    summary="Create a new HSM key version for the authorized organization",
    tags=["Key Version Services"],
)
def post_key_version(
    hsm_key_version_service: Annotated[
        HsmKeyVersionService, Depends(container.get_hsm_key_version_service)
    ],
    auth_ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
    req: HsmKeyVersionRequest | None = None,
) -> JSONResponse:
    try:
        entry = hsm_key_version_service.create_version_by_organization_external_id(
            auth_ctx.claims.organization_id,
            req.from_dt if req else None,
            req.until_dt if req else None,
        )
    except Exception:
        logger.exception(
            "failed to create key version for organization_id %s",
            auth_ctx.claims.organization_id,
        )
        raise HTTPException(status_code=500, detail="failed to create key version")

    return JSONResponse(status_code=201, content=jsonable_encoder(entry.to_dict()))


@router.get(
    "/key-versions",
    summary="List HSM key versions for the authorized organization",
    tags=["Key Version Services"],
)
def list_key_versions(
    hsm_key_version_service: Annotated[
        HsmKeyVersionService, Depends(container.get_hsm_key_version_service)
    ],
    auth_ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
) -> JSONResponse:
    versions = hsm_key_version_service.get_versions_by_organization_id(
        auth_ctx.claims.organization_id
    )
    return JSONResponse(
        status_code=200, content=jsonable_encoder([v.to_dict() for v in versions])
    )


@router.put(
    "/key-versions/{id}",
    summary="Update an HSM key version for the authorized organization",
    tags=["Key Version Services"],
)
def put_key_version(
    id: Annotated[UUID, Path(title="The ID of the key version to update")],
    req: HsmKeyVersionUpdateRequest,
    hsm_key_version_service: Annotated[
        HsmKeyVersionService, Depends(container.get_hsm_key_version_service)
    ],
    auth_ctx: Annotated[AuthContext, Depends(get_auth_ctx)],
) -> JSONResponse:
    try:
        entry = hsm_key_version_service.update_version_by_organization_id(
            id,
            auth_ctx.claims.organization_id,
            req.until_dt,
        )
    except HsmKeyVersionNotFoundError:
        logger.warning(
            "key version %s not found for organization %s",
            id,
            auth_ctx.claims.organization_id,
        )
        raise HTTPException(status_code=403, detail="forbidden")
    except Exception:
        logger.exception("failed to update key version %s", id)
        raise HTTPException(status_code=500, detail="failed to update key version")

    return JSONResponse(status_code=200, content=jsonable_encoder(entry))
