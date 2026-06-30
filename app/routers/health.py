import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.container import get_database
from app.db.db import Database

logger = logging.getLogger(__name__)
router = APIRouter()


def ok_or_error(value: bool) -> str:
    return "ok" if value else "error"


@router.get(
    "/health",
    summary="Health Check",
    description="health check for all dependent API services and components.",
    status_code=200,
    responses={
        200: {
            "description": "Health check completed (may contain unhealthy components)",
            "content": {
                "application/json": {
                    "examples": {
                        "all_healthy": {
                            "summary": "All services healthy",
                            "value": {
                                "status": "ok",
                                "components": {"database": "ok"},
                            },
                        },
                    }
                }
            },
        },
        500: {"description": "Unexpected error during health check execution"},
        503: {
            "description": "One or more components are unhealthy",
            "content": {
                "application/json": {
                    "examples": {
                        "some_unhealthy": {
                            "summary": "Some services unhealthy",
                            "value": {
                                "status": "error",
                                "components": {"database": "error"},
                            },
                        },
                    }
                }
            },
        },
    },
    tags=["Health"],
)
def health(
    db: Annotated[Database, Depends(get_database)],
) -> JSONResponse:
    logger.info("Checking application health")

    components = {
        "database": ok_or_error(db.is_healthy()),
    }
    healthy = ok_or_error(all(value == "ok" for value in components.values()))
    content = {"status": healthy, "components": components}
    if healthy == "ok":
        return JSONResponse(content=content)
    unhealthy = [name for name, status in components.items() if status != "ok"]
    logger.warning("Health check failed for components: %s", ", ".join(unhealthy))
    return JSONResponse(status_code=503, content=content)
