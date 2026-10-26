from app.enums.pseudonym_error_type import PseudonymErrorType
from app.exceptions.access import RecipientNotFoundError
from app.exceptions.base import AppError


class PseudonymError(AppError):
    pass


class InvalidPersonalIdError(PseudonymError):
    message = "Invalid personal ID"


class PseudonymOperationError(PseudonymError):
    """
    A failed key operation.
    """

    error_type: PseudonymErrorType


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
