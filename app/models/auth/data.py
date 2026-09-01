from enum import Enum


class AuthorizationScope(str, Enum):
    """OAuth scopes known to the PRS, forwarded by the OIN-verifier proxy in
    the x-gf-scope header (space separated, taken from the token's scope
    claim)."""

    SAML_REVERSIBLE_PSEUDONYM = "prs:saml-reversible-pseudonym"
