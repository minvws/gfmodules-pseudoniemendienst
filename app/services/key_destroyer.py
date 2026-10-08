from typing import Protocol

from app.models.oin import Oin


class KeyDestroyer(Protocol):
    def destroy(self, oin: Oin, version: int) -> bool:
        pass
