import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_VERSION_JSON_PATH = Path(__file__).resolve().parent.parent.parent / "version.json"
_version_cache: dict[str, Any] | None | bool = False


def load_version_json() -> dict[str, Any] | None:
    global _version_cache
    if _version_cache is not False:
        return _version_cache if isinstance(_version_cache, dict) else None

    try:
        with open(_VERSION_JSON_PATH, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.info("version info could not be loaded: %s", e)
        _version_cache = True
        return None
    if not isinstance(data, dict):
        logger.info("version info could not be loaded: not a JSON object")
        _version_cache = True
        return None
    _version_cache = data
    return data
