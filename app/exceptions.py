from app.enums.personal_id_type import PersonalIdType


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
    """The personal ID in the request is malformed."""

    message = "Invalid personal ID"


class InvalidPseudonymError(DomainError):
    """The pseudonym could not be decrypted or was not issued for this organization."""

    message = "Invalid pseudonym"


class PseudonymVersionDestroyedError(DomainError):
    """The pseudonym was issued under a key version that has since been destroyed."""

    message = "Pseudonym key version no longer available"


class PseudonymOperationError(ValueError):
    """Not a DomainError: callers translate error_type into either a mapped
    DomainError (client refusal) or a plain HTTPException (server failure,
    e.g. hsm_unreachable), so it must stay outside the DomainError status
    code map. error_type is one of: hsm_unreachable, crypto_failure,
    invalid_pseudonym, version_destroyed (reverse only), or
    no_active_key_version (generate only)."""

    def __init__(self, error_type: str, message: str) -> None:
        super().__init__(message)
        self.error_type = error_type
