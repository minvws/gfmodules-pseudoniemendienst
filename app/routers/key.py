import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import container
from app.auth import get_auth_ctx
from app.models.auth.context import AuthContext
from app.models.requests import RegisterRequest
from app.models.oin import Oin
from app.services.mtls_service import MtlsService
from app.services.key_resolver import KeyResolver, KeyRequest, AlreadyExistsError
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/register/certificate",
    summary="Insert public key information for an organization",
    tags=["Key Registration Services"],
)
def post_key(
    req: RegisterRequest,
    request: Request,
    mtls_service: MtlsService = Depends(container.get_mtls_service),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:

    mtls_pub_key = mtls_service.get_mtls_pub_key(request)
    org = mtls_service.get_org_from_request(request)

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
    "/keys/{oin}",
    summary="List public key information for an organization",
    tags=["Key Registration Services"],
)
def list_keys_for_org(
    oin: Oin,
    org_service: OrgService = Depends(container.get_org_service),
) -> JSONResponse:
    org = org_service.get_by_oin(oin.value)
    if org is None:
        logger.warning("organization for OIN %r not found", oin)
        raise HTTPException(
            status_code=400, detail="organization for this OIN is not registered"
        )

    if org.keys is None:
        logger.warning("no keys found for organization %s", org.id)
        raise HTTPException(status_code=404, detail="no keys found")

    return JSONResponse(status_code=200, content=[k.to_dict() for k in org.keys])


@router.put(
    "/keys/{key_id}",
    summary="Update specific key for key/scope",
    tags=["Key Registration Services"],
)
def put_key(
    key_id: str,
    req: KeyRequest,
    auth_ctx: AuthContext = Depends(get_auth_ctx),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:

    try:
        key_uuid = uuid.UUID(key_id)
    except ValueError:
        logger.warning("invalid key id: %r", key_id)
        raise HTTPException(status_code=400, detail="invalid key id")

    entry = key_resolver.get_by_id(key_uuid)
    if entry is None:
        logger.warning("key with id %r not found", key_id)
        raise HTTPException(status_code=404, detail="key not found")

    if entry.organization.oin != auth_ctx.claims.oin.value:
        raise HTTPException(status_code=403)

    key_resolver.update(entry.id, req.scope, req.pub_key)
    updated_entry = key_resolver.get_by_id(key_uuid)
    if updated_entry is None:
        logger.error("failed to retrieve updated key with id %r", key_id)
        raise HTTPException(status_code=500, detail="failed to retrieve updated key")

    return JSONResponse(status_code=200, content=updated_entry.to_dict())


@router.delete(
    "/keys/{key_id}",
    summary="Delete specific key for key/scope",
    tags=["Key Registration Services"],
)
def delete_key(
    key_id: str,
    auth_ctx: AuthContext = Depends(get_auth_ctx),
    key_resolver: KeyResolver = Depends(container.get_key_resolver),
) -> JSONResponse:
    try:
        key_uuid = uuid.UUID(key_id)
    except ValueError:
        logger.warning("invalid key id: %r", key_id)
        raise HTTPException(status_code=400, detail="invalid key id")

    entry = key_resolver.get_by_id(key_uuid)
    if entry is None:
        logger.warning("key with id %r not found", key_id)
        raise HTTPException(status_code=404, detail="key not found")

    if entry.organization.oin != auth_ctx.claims.oin.value:
        logger.warning(
            "caller oin=%s attempted to delete key %s owned by org %s",
            auth_ctx.claims.oin,
            key_id,
            entry.organization_id,
        )
        raise HTTPException(status_code=403, detail="forbidden")

    key_resolver.delete(entry.id)
    logger.info("key with id %s deleted successfully", key_id)
    return JSONResponse(status_code=200, content={"message": "key deleted"})
