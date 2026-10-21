from app.enums.personal_id_type import PersonalIdType
from app.exceptions.base import AppError


class AccessError(AppError):
    pass


class UnauthorizedRequestError(AccessError):
    """Malformed/missing proxy-verified headers, or a missing OAuth scope."""

    message = "Unauthorized request"


class InvalidAudienceError(AccessError):
    message = "Unauthorized request"


class OrganizationNotRegisteredError(AccessError):
    """The verified calling organization is not registered in the PRS."""

    message = "Organization does not exist"


class NotAllowedToRequestError(AccessError):
    """The calling organization may not request this type of personal id."""

    def __init__(self, personal_id_type: PersonalIdType) -> None:
        self.personal_id_type = personal_id_type
        super().__init__(f"Not allowed to request personal_id_type: {personal_id_type}")


class RecipientNotFoundError(AccessError):
    """
    The recipient organization is unknown, may not receive this type of
    personal id, or has no active key.
    """

    message = "Unable to find requested recipient organization"
