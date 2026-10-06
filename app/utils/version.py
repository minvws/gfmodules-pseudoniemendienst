import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_VERSION_JSON_PATH = Path(__file__).resolve().parent.parent.parent / "version.json"


def load_version_json() -> dict[str, Any] | None:
    try:
        with open(_VERSION_JSON_PATH, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.info("version info could not be loaded: %s", e)
        return None
    if not isinstance(data, dict):
        logger.info("version info could not be loaded: not a JSON object")
        return None
    return data
