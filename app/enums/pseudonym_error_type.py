from enum import StrEnum


class PseudonymErrorType(StrEnum):
    NO_ACTIVE_KEY_VERSION = "no_active_key_version"
    HSM_UNREACHABLE = "hsm_unreachable"
    CRYPTO_FAILURE = "crypto_failure"
    VERSION_DESTROYED = "version_destroyed"
    INVALID_PSEUDONYM = "invalid_pseudonym"
    INVALID_BLINDED_INPUT = "invalid_blinded_input"
    CRYPTO_EVALUATION_FAILURE = "crypto_evaluation_failure"
