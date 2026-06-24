import logging

from fastapi import HTTPException

from app.models.auth.headers import AuthHeaders

logger = logging.getLogger(__name__)


class AuthHeaderService:
    def __init__(self, expected_audience: str) -> None:
        self.expected_audience = expected_audience

    def validate(self, auth_headers: AuthHeaders) -> AuthHeaders:
        audience = auth_headers.audience

        if audience != self.expected_audience:
            logger.error(
                f"Invalid audience value {audience} value should be {self.expected_audience}. Check config values in case incoming value is correct"
            )
            raise HTTPException(status_code=403, detail="Unauthorized request")

        return auth_headers
