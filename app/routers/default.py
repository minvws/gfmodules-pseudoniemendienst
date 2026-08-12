import json
import logging
from pathlib import Path

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse, PlainTextResponse

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


@router.get(
    "/",
    summary="Service banner and version information",
    tags=["Service Information"],
)
def index() -> Response:
    content = LOGO

    try:
        with open(Path(__file__).parent.parent.parent / "version.json", "r") as file:
            data = json.load(file)
            content += "\nVersion: {}\nCommit: {}".format(data["version"], data["git_ref"])
    except (OSError, json.JSONDecodeError, KeyError) as e:
        content += "\nNo version information found"
        logger.info(f"version info could not be loaded: {e}")

    return PlainTextResponse(content)


@router.get(
    "/version.json",
    summary="Service version as JSON",
    tags=["Service Information"],
)
def version_json() -> Response:
    try:
        with open(Path(__file__).parent.parent.parent / "version.json", "r") as file:
            content = json.load(file)
    except (OSError, json.JSONDecodeError) as e:
        logger.info(f"version info could not be loaded: {e}")
        return Response(status_code=404)

    return JSONResponse(content)
