from app.exceptions.base import AppError


class RegistrationError(AppError):
    pass


class InvalidJwsError(RegistrationError):
    """The self-signed JWS carrying a public key was rejected."""


class PublicKeyNotFoundError(RegistrationError):
    message = "public key not found"


class DomainAlreadyRegisteredError(RegistrationError):
    """One of the requested domains already belongs to another key."""

    message = "key for this org/scope already exists"


class DomainNotRegisteredError(RegistrationError):
    """The recipient has no key for the requested scope and no wildcard key."""

    message = "Organization domain is not registered"


class KeyVersionNotFoundError(RegistrationError):
    message = "KeyVersion not found"


class KeyVersionRemovedError(RegistrationError):
    message = "KeyVersion has been removed"


class NoKeyVersionError(RegistrationError):
    """The organization has no key version to rotate from."""

    message = "Organization has no key version"
