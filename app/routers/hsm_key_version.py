import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

from app import container
from app.models.oin import Oin
from app.models.requests import (
    OIN_PATTERN,
    HsmKeyVersionRequest,
    HsmKeyVersionUpdateRequest,
)
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/key-versions",
    summary="Create a new HSM key version for an organization",
    tags=["Key Version Services"],
)
def post_key_version(
    req: HsmKeyVersionRequest,
    hsm_key_version_service: HsmKeyVersionService = Depends(
        container.get_hsm_key_version_service
    ),
) -> JSONResponse:
    try:
        entry = hsm_key_version_service.create_version(
            req.oin, req.from_dt, req.until_dt
        )
    except ValueError as e:
        logger.warning("cannot create key version: %s", e)
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        logger.exception("failed to create key version for OIN %s", req.oin)
        raise HTTPException(status_code=500, detail="failed to create key version")

    return JSONResponse(status_code=201, content=jsonable_encoder(entry.to_dict()))


@router.get(
    "/key-versions/{oin}",
    summary="List HSM key versions for an organization",
    tags=["Key Version Services"],
)
def list_key_versions(
    oin: Oin,
    hsm_key_version_service: HsmKeyVersionService = Depends(
        container.get_hsm_key_version_service
    ),
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    org = org_service.get_by_oin(oin.value)
    if org is None:
        logger.warning("organization for OIN %r not found", oin.value)
        raise HTTPException(status_code=404, detail="organization not found")

    versions = hsm_key_version_service.get_versions_for_oin(oin)
    return JSONResponse(
        status_code=200, content=jsonable_encoder([v.to_dict() for v in versions])
    )


@router.put(
    "/key-versions/{id}",
    summary="Update an HSM key version (end date and/or removed flag)",
    tags=["Key Version Services"],
)
def put_key_version(
    id: UUID,
    req: HsmKeyVersionUpdateRequest,
    hsm_key_version_service: HsmKeyVersionService = Depends(
        container.get_hsm_key_version_service
    ),
) -> JSONResponse:
    try:
        entry = hsm_key_version_service.update_version(id, req.until_dt, req.removed)
    except Exception:
        logger.exception("failed to update key version %s", id)
        raise HTTPException(status_code=500, detail="failed to update key version")

    if entry is None:
        logger.warning("key version with id %r not found", id)
        raise HTTPException(status_code=404, detail="key version not found")

    return JSONResponse(status_code=200, content=jsonable_encoder(entry.to_dict()))
