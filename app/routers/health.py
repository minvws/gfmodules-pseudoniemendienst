import logging
from typing import Any

from fastapi import APIRouter, Depends

from app import container

from app.services.rid_service import RidService

logger = logging.getLogger(__name__)
router = APIRouter()


def ok_or_error(value: bool) -> str:
    return "ok" if value else "error"


@router.get("/health")
def health(rid_service: RidService = Depends(container.get_rid_service)) -> dict[str, Any]:
    components = {
        'rid': ok_or_error(rid_service.is_healthy()),
    }
    healthy = ok_or_error(all(value == "ok" for value in components.values()))

    return {
        "status": healthy,
        "components": components
    }
