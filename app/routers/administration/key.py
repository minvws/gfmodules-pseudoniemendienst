import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import container
from app.auth import authenticated_oin
from app.models.requests import RegisterRequest
from app.models.oin import Oin
from app.services.mtls_service import MtlsService
from app.services.key_resolver import KeyResolver, KeyRequest, AlreadyExistsError
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/register/certificate",
    summary="Insert public key information for the authorized organization",
    tags=["Key Registration Services"],
)
def post_key(
    req: RegisterRequest,
    request: Request,
    auth_oin: Oin = Depends(authenticated_oin),
    org_service: OrgService = Depends(container.get_org_service),
    mtls_service: MtlsService = Depends(container.get_mtls_service),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:

    mtls_pub_key = mtls_service.get_mtls_pub_key(request)
    org = org_service.get_by_oin(auth_oin)
    if org is None:
        logger.warning(
            "caller oin %s has no registered organization when registering key",
            auth_oin,
        )
        raise HTTPException(
            status_code=400,
            detail=f"organization for OIN {auth_oin.value} is not registered",
        )

    if org.oin != auth_oin:
        logger.warning(
            "caller oin=%s attempted to register key for org %s",
            auth_oin,
            org.oin,
        )
        raise HTTPException(status_code=403, detail="forbidden")

    # Create the key entry
    try:
        key_resolver.create(org.id, req.scope, req.key_id, mtls_pub_key)
    except AlreadyExistsError:
        logger.warning("key already exists for org_id=%s scope=%r", org.id, req.scope)
        raise HTTPException(
            status_code=409, detail="key for this org/scope already exists"
        )
    except Exception:
        logger.exception(
            "failed to create key entry for org_id=%s scope=%r", org.id, req.scope
        )
        raise HTTPException(status_code=500, detail="failed to create key entry")

    return JSONResponse(
        status_code=201, content={"message": "Key created successfully"}
    )


@router.get(
    "/keys",
    summary="List public key information for the authorized organization",
    tags=["Key Registration Services"],
)
def list_keys_for_org(
    auth_oin: Oin = Depends(authenticated_oin),
    org_service: OrgService = Depends(container.get_org_service),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:
    org = org_service.get_by_oin(auth_oin)
    if org is None:
        logger.warning("organization for OIN %r not found", auth_oin)
        raise HTTPException(
            status_code=400, detail="organization for this OIN is not registered"
        )

    entries = key_resolver.get_by_org(org.id)

    return JSONResponse(status_code=200, content=[k.to_dict() for k in entries])


@router.put(
    "/keys/{key_id}",
    summary="Update a key for the authorized organization",
    tags=["Key Registration Services"],
)
def put_key(
    key_id: Annotated[UUID, Path(title="The ID of the key to update")],
    req: KeyRequest,
    auth_oin: Oin = Depends(authenticated_oin),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:
    entry = key_resolver.get_by_id(key_id)
    if entry is None:
        logger.warning("key with id %r not found", key_id)
        raise HTTPException(status_code=404, detail="key not found")

    if entry.organization.oin != auth_oin:
        raise HTTPException(status_code=403)

    key_resolver.update(entry.id, req.scope, req.pub_key)
    updated_entry = key_resolver.get_by_id(key_id)
    if updated_entry is None:
        logger.error("failed to retrieve updated key with id %r", key_id)
        raise HTTPException(status_code=500, detail="failed to retrieve updated key")

    return JSONResponse(status_code=200, content=updated_entry.to_dict())


@router.delete(
    "/keys/{key_id}",
    summary="Delete a key for the authorized organization",
    tags=["Key Registration Services"],
)
def delete_key(
    key_id: Annotated[UUID, Path(title="The ID of the key to delete")],
    auth_oin: Oin = Depends(authenticated_oin),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:
    entry = key_resolver.get_by_id(key_id)
    if entry is None:
        logger.warning("key with id %r not found", key_id)
        raise HTTPException(status_code=404, detail="key not found")

    if entry.organization.oin != auth_oin:
        logger.warning(
            "caller oin=%s attempted to delete key %s owned by org %s",
            auth_oin,
            key_id,
            entry.organization_id,
        )
        raise HTTPException(status_code=403, detail="forbidden")

    key_resolver.delete(entry.id)
    logger.info("key with id %s deleted successfully", key_id)
    return JSONResponse(status_code=200, content={"message": "key deleted"})
