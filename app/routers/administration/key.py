import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import container
from app.auth import authenticated_organization
from app.db.entities.organization import Organization
from app.models.requests import RegisterRequest
from app.services.mtls_service import MtlsService
from app.services.key_resolver import KeyResolver, KeyRequest, AlreadyExistsError

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
    auth_org: Annotated[Organization, Depends(authenticated_organization)],
    mtls_service: Annotated[MtlsService, Depends(container.get_mtls_service)],
    key_resolver: Annotated[KeyResolver, Depends(container.get_key_resolver)],
) -> JSONResponse:
    mtls_pub_key = mtls_service.get_mtls_pub_key(request)

    # Create the key entry
    try:
        key_resolver.create(auth_org.id, req.scope, req.key_id, mtls_pub_key)
    except AlreadyExistsError:
        logger.warning(
            "key already exists for org_id=%s scope=%r", auth_org.id, req.scope
        )
        raise HTTPException(
            status_code=409, detail="key for this org/scope already exists"
        )
    except Exception:
        logger.exception(
            "failed to create key entry for org_id=%s scope=%r", auth_org.id, req.scope
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
    auth_org: Annotated[Organization, Depends(authenticated_organization)],
    key_resolver: Annotated[KeyResolver, Depends(container.get_key_resolver)],
) -> JSONResponse:
    entries = key_resolver.get_by_org(auth_org.id)

    return JSONResponse(status_code=200, content=[k.to_dict() for k in entries])


@router.put(
    "/keys/{key_id}",
    summary="Update a key for the authorized organization",
    tags=["Key Registration Services"],
)
def put_key(
    key_id: Annotated[UUID, Path(title="The ID of the key to update")],
    req: KeyRequest,
    auth_org: Annotated[Organization, Depends(authenticated_organization)],
    key_resolver: Annotated[KeyResolver, Depends(container.get_key_resolver)],
) -> JSONResponse:
    try:
        updated = key_resolver.update(
            key_id,
            req.scope,
            req.pub_key,
            auth_org.id,
        )
    except AlreadyExistsError:
        logger.warning(
            "key already exists for org_id=%s scope=%r", auth_org.id, req.scope
        )
        raise HTTPException(
            status_code=409, detail="key for this org/scope already exists"
        )

    if updated is None:
        logger.warning(
            "key %s for organization %s was not updated", key_id, auth_org.id
        )
        raise HTTPException(status_code=404, detail="key not found")

    return JSONResponse(status_code=200, content=updated.to_dict())


@router.delete(
    "/keys/{key_id}",
    summary="Delete a key for the authorized organization",
    tags=["Key Registration Services"],
)
def delete_key(
    key_id: Annotated[UUID, Path(title="The ID of the key to delete")],
    auth_org: Annotated[Organization, Depends(authenticated_organization)],
    key_resolver: Annotated[KeyResolver, Depends(container.get_key_resolver)],
) -> JSONResponse:
    if not key_resolver.delete(key_id, auth_org.id):
        logger.warning(
            "key %s for organization %s was not deleted", key_id, auth_org.id
        )
        raise HTTPException(status_code=404, detail="key not found")

    logger.info("key with id %s deleted successfully", key_id)
    return JSONResponse(status_code=200, content={"message": "key deleted"})
