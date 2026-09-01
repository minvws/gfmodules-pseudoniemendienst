from enum import Enum


class AuthorizationScope(str, Enum):
    ADMINISTRATION = "prs:administration"
    OPRF = "prs:oprf"
    PSEUDONYM = "prs:pseudonym"
    REVERSIBLE_PSEUDONYM = "prs:reversible-pseudonym"


SCOPE_DESCRIPTIONS: dict[AuthorizationScope, str] = {
    AuthorizationScope.ADMINISTRATION: (
        "Manage the public keys and HSM key versions of the authorized organization."
    ),
    AuthorizationScope.OPRF: (
        "Evaluate a blinded personal identifier through the OPRF."
    ),
    AuthorizationScope.PSEUDONYM: (
        "Exchange a personal ID for an irreversible pseudonym."
    ),
    AuthorizationScope.REVERSIBLE_PSEUDONYM: (
        "Exchange a personal ID for a reversible pseudonym or a BSN."
    ),
}
