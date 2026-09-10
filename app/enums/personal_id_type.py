from enum import StrEnum


class PersonalIdType(StrEnum):
    OPRF = "oprf"
    REVERSIBLE_PSEUDONYM = "reversible_pseudonym"
    IRREVERSIBLE_PSEUDONYM = "irreversible_pseudonym"
