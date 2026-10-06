import json
from pathlib import Path
from typing import Any

_VERSION_JSON_PATH = Path(__file__).resolve().parent.parent.parent / "version.json"


def load_version_json() -> dict[str, Any] | None:
    try:
        with open(_VERSION_JSON_PATH, "r") as f:
            data: dict[str, Any] = json.load(f)
            return data
    except (OSError, json.JSONDecodeError):
        return None
