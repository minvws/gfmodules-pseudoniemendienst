import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse

from app import container
from app.models.requests import HsmKeyVersionRequest, HsmKeyVersionUpdateRequest
from app.services.hsm_key_version_service import HsmKeyVersionService

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
            req.ura, req.from_dt, req.until_dt
        )
    except ValueError as e:
        logger.warning("cannot create key version: %s", e)
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        logger.exception("failed to create key version for ura %s", req.ura)
        raise HTTPException(status_code=500, detail="failed to create key version")

    return JSONResponse(status_code=201, content=jsonable_encoder(entry.to_dict()))


@router.put(
    "/key-versions/{version_id}",
    summary="Update an HSM key version (end date and/or removed flag)",
    tags=["Key Version Services"],
)
def put_key_version(
    version_id: str,
    req: HsmKeyVersionUpdateRequest,
    hsm_key_version_service: HsmKeyVersionService = Depends(
        container.get_hsm_key_version_service
    ),
) -> JSONResponse:
    try:
        version_uuid = uuid.UUID(version_id)
    except ValueError:
        logger.warning("invalid key version id: %r", version_id)
        raise HTTPException(status_code=400, detail="invalid key version id")

    try:
        entry = hsm_key_version_service.update_version(
            version_uuid, req.until_dt, req.removed
        )
    except Exception:
        logger.exception("failed to update key version %s", version_id)
        raise HTTPException(status_code=500, detail="failed to update key version")

    if entry is None:
        logger.warning("key version with id %r not found", version_id)
        raise HTTPException(status_code=404, detail="key version not found")

    return JSONResponse(status_code=200, content=jsonable_encoder(entry.to_dict()))
