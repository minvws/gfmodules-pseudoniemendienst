import base64
import json
import logging
import os

logger = logging.getLogger(__name__)

class JsonKeyStorage:
    """
    Key storage class that stores keys in memory and on disk. This is useful for testing and development. Do not use
    this in production.
    """
    def __init__(self, path: str) -> None:
        self.path = path

        try:
            with open(path, "r") as f:
                data = json.load(f)
        except Exception:
            data = {}

        self.keys = {key: base64.b64decode(value) for key, value in data.items()}
        logger.info(f"Loaded {len(self.keys)} key(s) from disk")

    def generate_key(self, key_id: str) -> None:
        self.keys[key_id] = os.urandom(32)
        logger.info(f"Generated key with ID {key_id}")

        encoded_data = {key: base64.b64encode(value).decode('utf-8') for key, value in self.keys.items()}
        with open(self.path, "w") as f:
            json.dump(encoded_data, f, indent=4)

    def has_key(self, key_id: str) -> bool:
        return key_id in self.keys

    def get_key(self, key_id: str) -> bytes:
        return self.keys[key_id]
