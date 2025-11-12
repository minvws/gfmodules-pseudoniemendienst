import logging
from typing import Any

from fastapi import APIRouter



logger = logging.getLogger(__name__)
router = APIRouter()


def ok_or_error(value: bool) -> str:
    return "ok" if value else "error"


@router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
    }
