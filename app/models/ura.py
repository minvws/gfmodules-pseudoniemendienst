from dataclasses import dataclass
from typing import Any


@dataclass
class UraNumber:
    """
    Representation of an URA Number, where it can adhere to the requirements
    of that number.
    See: https://www.zorgcsp.nl/documents/10-01-2025%20RK1%20CPS%20UZI-register%20V11.9%20NL.pdf
    """

    def __init__(self, value: Any) -> None:
        if (isinstance(value, int) or isinstance(value, str)) and len(str(value)) <= 8 and str(value).isdigit():
            self.value = str(value).zfill(8)
        else:
            raise ValueError("URA number must be 8 digits or less")

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"UraNumber({self.value})"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, UraNumber):
            return self.value == other.value
        return False
