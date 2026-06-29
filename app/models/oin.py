import re
from typing import Any

from pydantic import GetCoreSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import PydanticCustomError, core_schema

# An OIN is always 20 characters:
#   prefix (8 digits) + mainnumber (8 or 9 alphanumeric) + suffix (4 or 3 zeros)
OIN_PATTERN = re.compile(r"^\d{8}(?:[A-Za-z0-9]{8}0{4}|[A-Za-z0-9]{9}0{3})$")
RECIPIENT_ORGANIZATION_PREFIX = "oin:"
_RECIPIENT_ORGANIZATION_SUFFIX_PATTERN = (
    r"\d{8}(?:[A-Za-z0-9]{8}0{4}|[A-Za-z0-9]{9}0{3})"
)
RECIPIENT_ORGANIZATION_PATTERN = re.compile(
    rf"^{RECIPIENT_ORGANIZATION_PREFIX}{_RECIPIENT_ORGANIZATION_SUFFIX_PATTERN}$"
)


class Oin:
    """
    Value object representing a Dutch OIN (Organisatie Identificatie nummer).

    An OIN is exactly 20 positions long (matching the PKIoverheid certificate
    subject serial number field) and consists of three parts:

      - Prefix       (8 positions): digits identifying the issuing authority / register.
      - mainnumber  (8 or 9 positions): identifying number from the register.
        Can be alphanumeric depending on the register used.
        When the source is a KvK number the mainnumber is 8 positions.
      - Suffix       (3 or 4 positions, always zeros):
          - "0000" when the mainnumber is 8 positions.
          - "000"  when the mainnumber is 9 positions.

    https://gitdocumentatie.logius.nl/publicatie/dk/oin/3.0.0/#samenstelling-oin
    """

    PREFIX_LENGTH = 8
    TOTAL_LENGTH = 20

    _LONG_SUFFIX = "0000"  # used when mainnumber is 8 digits
    _SHORT_SUFFIX = "000"  # used when mainnumber is 9 digits

    def __init__(self, value: Any) -> None:
        if isinstance(value, Oin):
            value = value.value

        if not isinstance(value, (int, str)):
            raise ValueError(
                f"OIN must be a string or integer, got {type(value).__name__}"
            )

        if isinstance(value, int) and value < 0:
            raise ValueError("OIN must be a positive integer")

        str_value = str(value)

        if not OIN_PATTERN.match(str_value):
            raise ValueError(
                f"Invalid OIN {str_value!r}. "
                f"Expected {self.TOTAL_LENGTH} characters structured as "
                f"8 digit prefix + 8/9 alphanumeric mainnumber + 4/3 trailing zeros."
            )

        self.prefix = str_value[: self.PREFIX_LENGTH]
        self.number = str_value[self.PREFIX_LENGTH :]

    @property
    def mainnumber(self) -> str:
        """
        The identifying part of the OIN (8 or 9 characters, alphanumeric).
        8 characters when the suffix is "0000"; 9 characters when the suffix is "000".
        """
        if self.number.endswith(self._LONG_SUFFIX):
            return self.number[
                : self.TOTAL_LENGTH - self.PREFIX_LENGTH - len(self._LONG_SUFFIX)
            ]
        return self.number[
            : self.TOTAL_LENGTH - self.PREFIX_LENGTH - len(self._SHORT_SUFFIX)
        ]

    @property
    def suffix(self) -> str:
        """The trailing zero-padding ("0000" when mainnumber is 8 chars, "000" when 9 chars)."""
        if self.number.endswith(self._LONG_SUFFIX):
            return self._LONG_SUFFIX
        return self._SHORT_SUFFIX

    @property
    def value(self) -> str:
        return self.prefix + self.number

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"Oin({self.prefix}, {self.number})"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Oin):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return False

    def __hash__(self) -> int:
        return hash(self.value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source_type: Any, _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._pydantic_validate,
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def _pydantic_validate(cls, value: Any) -> "Oin":
        if isinstance(value, cls):
            return value
        try:
            return cls(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(str(exc)) from exc

    @classmethod
    def __get_pydantic_json_schema__(
        cls, _schema: core_schema.CoreSchema, _handler: Any
    ) -> JsonSchemaValue:
        return {
            "type": "string",
            "pattern": r"^\d{8}(?:[A-Za-z0-9]{8}0{4}|[A-Za-z0-9]{9}0{3})$",
            "examples": ["00000099000000001000"],
            "description": (
                "OIN (Organisatie Identificatie nummer): 20 characters structured as "
                "8-digit prefix + 8/9-character alphanumeric mainnumber + 4/3 trailing zeros (suffix)."
            ),
        }


class RecipientOrganizationOin(Oin):
    """An OIN supplied with recipient organization prefix, e.g. ``oin:<oin>``.

    Internally the stored value remains a plain OIN without the ``oin:`` prefix.
    """

    PREFIX = RECIPIENT_ORGANIZATION_PREFIX
    _INVALID_ERROR = "Invalid recipient organization. Format: oin:<oin_number>"

    def __init__(self, value: Any) -> None:
        if isinstance(value, str) and value.startswith(self.PREFIX):
            value = value[len(self.PREFIX) :]
        super().__init__(value)

    @classmethod
    def _pydantic_validate(cls, value: Any) -> "RecipientOrganizationOin":
        if isinstance(value, cls):
            return value

        if isinstance(value, Oin):
            return cls(value.value)

        if not isinstance(value, str):
            raise PydanticCustomError(
                "invalid_recipient_organization", cls._INVALID_ERROR
            )

        if not value.startswith(cls.PREFIX):
            raise PydanticCustomError(
                "invalid_recipient_organization", cls._INVALID_ERROR
            )

        try:
            return cls(value[len(cls.PREFIX) :])
        except ValueError as e:
            raise PydanticCustomError(
                "invalid_recipient_organization", "{error}", {"error": str(e)}
            ) from e

    @classmethod
    def __get_pydantic_core_schema__(
        cls, _source_type: Any, _handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._pydantic_validate,
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, _schema: core_schema.CoreSchema, _handler: Any
    ) -> JsonSchemaValue:
        return {
            "type": "string",
            "pattern": RECIPIENT_ORGANIZATION_PATTERN.pattern,
            "examples": [f"{RECIPIENT_ORGANIZATION_PREFIX}00000099000000001000"],
            "description": (
                "Recipient organization string: prefix followed by an OIN (20-char "
                "identifier)."
            ),
        }

    def __str__(self) -> str:
        """Return the recipient organization OIN in external format, including ``oin:``."""
        return f"{self.PREFIX}{self.value}"

    @property
    def value(self) -> str:
        """Return the normalized OIN value without the ``oin:`` prefix."""
        return super().value
