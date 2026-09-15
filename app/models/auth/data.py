from enum import StrEnum


class AuthorizationScope(StrEnum):
    ADMINISTRATION = "prs:administration"
    PSEUDONYM = "prs:pseudonym"
    OPRF_PSEUDONYM = "prs:oprf-pseudonym"
    SAML_PSEUDONYM = "prs:saml-pseudonym"


SCOPE_DESCRIPTIONS: dict[AuthorizationScope, str] = {
    AuthorizationScope.ADMINISTRATION: (
        "This scope gives authorization to manage administration features for the authorized organization"
    ),
    AuthorizationScope.PSEUDONYM: (
        "This scope gives authorization to use the general pseudonymisation feature of the Pseudoniemendienst"
    ),
    AuthorizationScope.OPRF_PSEUDONYM: (
        "This scope gives authorization to use the oprf pseudonymisation feature of the Pseudoniemendienst"
    ),
    AuthorizationScope.SAML_PSEUDONYM: (
        "This scope gives authorization to use the saml pseudonymisation feature of the Pseudoniemendienst"
    ),
}
