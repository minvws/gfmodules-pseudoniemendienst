import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.container import get_jwks_service
from app.services.jwks.service import JwksService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/.well-known")


@router.get("/jwks")
def get_jwks(
    jwks_service: Annotated[JwksService, Depends(get_jwks_service)],
) -> Any:
    return jwks_service.get_jwks()
