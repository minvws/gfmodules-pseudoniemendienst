import logging

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from app.config import get_config
from app.features import enabled_features
from app.utils.version import load_version_json

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

    data = load_version_json()
    if data and "version" in data and "git_ref" in data:
        content += "\nVersion: {}\nCommit: {}".format(data["version"], data["git_ref"])
    else:
        content += "\nNo version information found"
        logger.info("version info could not be loaded")

    return PlainTextResponse(content)


@router.get(
    "/version.json",
    summary="Service version and enabled features as JSON",
    description=(
        "Returns the build version information, extended with the features "
        "enabled by the configuration of this environment."
    ),
    tags=["Service Information"],
)
def version_json() -> Response:
    content = load_version_json()
    if content is None:
        logger.info("version info could not be loaded")
        return Response(status_code=404)

    content["features"] = [
        feature.model_dump() for feature in enabled_features(get_config())
    ]
    return JSONResponse(content)
