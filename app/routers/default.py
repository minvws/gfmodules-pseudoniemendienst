import logging

from fastapi import APIRouter, Response

logger = logging.getLogger(__name__)
router = APIRouter()

# https://www.patorjk.com/software/taag/#p=display&f=Doom&t=Skeleton
LOGO = r"""
____________  _____ 
| ___ \ ___ \/  ___|
| |_/ / |_/ /\ `--. 
|  __/|    /  `--. \
| |   | |\ \ /\__/ /
\_|   \_| \_|\____/ 
"""


@router.get("/")
def index() -> Response:
    return Response(LOGO)
