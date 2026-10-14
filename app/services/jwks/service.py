from typing import Any

from app.services.jwks.keys import JwksKeyService


class JwksService:
    def __init__(self, jwks_key_service: JwksKeyService) -> None:
        self.jwks_key_service = jwks_key_service

    def get_jwks(self) -> dict[str, Any]:
        return self.jwks_key_service.get_jwks()
