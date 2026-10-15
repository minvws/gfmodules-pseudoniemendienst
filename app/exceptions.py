"""
Domain exceptions raised by the service layer.
"""

from app.enums.personal_id_type import PersonalIdType
from app.enums.pseudonym_error_type import PseudonymErrorType


class DomainError(Exception):
    """Base class for errors the service layer reports to its callers."""

    message: str = "Request could not be processed"

    def __init__(self, message: str | None = None) -> None:
        if message is not None:
            self.message = message
        super().__init__(self.message)


class OrganizationNotRegisteredError(DomainError):
    """The verified calling organization is not registered in the PRS."""

    message = "Organization does not exist"


class NotAllowedToRequestError(DomainError):
    """The calling organization may not request this type of personal id."""

    def __init__(self, personal_id_type: PersonalIdType) -> None:
        self.personal_id_type = personal_id_type
        super().__init__(f"Not allowed to request personal_id_type: {personal_id_type}")


class RecipientNotFoundError(DomainError):
    """
    The recipient organization is unknown, may not receive this type of
    personal id, or has no active key.
    """

    message = "Unable to find requested recipient organization"


class InvalidJwsError(DomainError):
    """The self-signed JWS carrying a public key was rejected."""


class PublicKeyNotFoundError(DomainError):
    message = "public key not found"


class DomainAlreadyRegisteredError(DomainError):
    """One of the requested domains already belongs to another key."""

    message = "key for this org/scope already exists"


class DomainNotRegisteredError(DomainError):
    """The recipient has no key for the requested scope and no wildcard key."""

    message = "Organization domain is not registered"


class KeyVersionNotFoundError(DomainError):
    message = "KeyVersion not found"


class KeyVersionRemovedError(DomainError):
    message = "KeyVersion has been removed"


class NoKeyVersionError(DomainError):
    """The organization has no key version to rotate from."""

    message = "Organization has no key version"


class InvalidAudienceError(DomainError):
    message = "Unauthorized request"


class UnauthorizedRequestError(DomainError):
    """Malformed/missing proxy-verified headers, or a missing OAuth scope."""

    message = "Unauthorized request"


class InvalidPersonalIdError(DomainError):
    message = "Invalid personal ID"


class PseudonymOperationError(DomainError):
    """
    A failed key operation.
    """

    error_type: PseudonymErrorType

    def __init__(self, reason: str) -> None:
        super().__init__()
        self.reason = reason

    def __str__(self) -> str:
        return self.reason


class InvalidPseudonymError(PseudonymOperationError):
    error_type = PseudonymErrorType.INVALID_PSEUDONYM
    message = "Invalid pseudonym"


class InvalidBlindedInputError(PseudonymOperationError):
    error_type = PseudonymErrorType.INVALID_BLINDED_INPUT
    message = "Invalid blinded input"


class PseudonymVersionDestroyedError(PseudonymOperationError):
    error_type = PseudonymErrorType.VERSION_DESTROYED
    message = "Pseudonym key version no longer available"


class NoActiveKeyVersionError(PseudonymOperationError):
    error_type = PseudonymErrorType.NO_ACTIVE_KEY_VERSION
    message = RecipientNotFoundError.message


class CryptoFailureError(PseudonymOperationError):
    error_type = PseudonymErrorType.CRYPTO_FAILURE
    message = "Pseudonym exchange failed"


class HsmOperationFailedError(PseudonymOperationError):
    error_type = PseudonymErrorType.HSM_OPERATION_FAILED
    message = "Pseudonym operation failed"


class HsmUnreachableError(PseudonymOperationError):
    error_type = PseudonymErrorType.HSM_UNREACHABLE
    message = "Service temporarily unavailable"


class HsmTimeoutError(PseudonymOperationError):
    error_type = PseudonymErrorType.HSM_TIMEOUT
    message = "Service temporarily unavailable"


class ExchangeInputError(DomainError):
    message = "Exactly one of personalId or reversiblePseudonym must be provided"
