import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

from app import container
from app.auth import authenticated_oin
from app.models.oin import Oin
from app.models.requests import HsmKeyVersionRequest, HsmKeyVersionUpdateRequest
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.hsm_key_version_service import HsmKeyVersionNotFoundError

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/key-versions",
    summary="Create a new HSM key version for the authorized organization",
    tags=["Key Version Services"],
)
def post_key_version(
    req: HsmKeyVersionRequest,
    auth_oin: Oin = Depends(authenticated_oin),
    hsm_key_version_service: HsmKeyVersionService = Depends(
        container.get_hsm_key_version_service
    ),
) -> JSONResponse:
    try:
        entry = hsm_key_version_service.create_version(
            auth_oin, req.from_dt, req.until_dt
        )
    except Exception:
        logger.exception("failed to create key version for OIN %s", auth_oin)
        raise HTTPException(status_code=500, detail="failed to create key version")

    return JSONResponse(status_code=201, content=jsonable_encoder(entry.to_dict()))


@router.get(
    "/key-versions",
    summary="List HSM key versions for the authorized organization",
    tags=["Key Version Services"],
)
def list_key_versions(
    auth_oin: Oin = Depends(authenticated_oin),
    hsm_key_version_service: HsmKeyVersionService = Depends(
        container.get_hsm_key_version_service
    ),
) -> JSONResponse:
    versions = hsm_key_version_service.get_versions_for_oin(auth_oin)
    return JSONResponse(
        status_code=200, content=jsonable_encoder([v.to_dict() for v in versions])
    )


@router.put(
    "/key-versions/{id}",
    summary="Update an HSM key version for the authorized organization",
    tags=["Key Version Services"],
)
def put_key_version(
    id: UUID,
    req: HsmKeyVersionUpdateRequest,
    auth_oin: Oin = Depends(authenticated_oin),
    hsm_key_version_service: HsmKeyVersionService = Depends(
        container.get_hsm_key_version_service
    ),
) -> JSONResponse:
    try:
        entry = hsm_key_version_service.update_version(id, auth_oin, req.until_dt)
    except HsmKeyVersionNotFoundError:
        logger.warning("key version %s not found for OIN %s", id, auth_oin)
        raise HTTPException(status_code=404, detail="key version not found")
    except Exception:
        logger.exception("failed to update key version %s", id)
        raise HTTPException(status_code=500, detail="failed to update key version")

    return JSONResponse(status_code=200, content=jsonable_encoder(entry.to_dict()))
