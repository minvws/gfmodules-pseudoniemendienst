from fastapi import APIRouter

from app.routers.exchange.irreversible_pseudonym import (
    router as irreversible_pseudonym_router,
)
from app.routers.exchange.reversible_pseudonym import (
    router as reversible_pseudonym_router,
)

router = APIRouter(prefix="/exchange", tags=["Exchange Services"])
router.include_router(reversible_pseudonym_router)
router.include_router(irreversible_pseudonym_router)
