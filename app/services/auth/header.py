import logging

import gfmodules.logging as gflog

from app.exceptions.access import InvalidAudienceError
from app.logging.events import Log
from app.models.auth.headers import AuthHeaders

logger = logging.getLogger(__name__)


class AuthHeaderService:
    def __init__(self, expected_audiences: list[str]) -> None:
        self.expected_audiences = expected_audiences

    def validate(self, auth_headers: AuthHeaders) -> AuthHeaders:
        audience = auth_headers.audience

        if audience not in self.expected_audiences:
            gflog.emit(
                logger,
                Log.AUTHORIZATION_DENIED,
                f"audience {audience!r} is not one of {self.expected_audiences}",
                fields={
                    "acting_organization_identifier": str(
                        auth_headers.client_organization_id
                    ),
                    "represented_organization_identifier": str(
                        auth_headers.organization_id
                    ),
                    "error_reason": "audience_not_accepted",
                },
            )
            raise InvalidAudienceError()

        return auth_headers
