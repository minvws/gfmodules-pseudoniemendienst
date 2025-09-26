import json
from typing import Any

ALLOWED_ID_TYPES = {"bsn"}

class PersonalId:
    def __init__(self, country_code: str, id_type: str, id_number: str) -> None:
        if not country_code or len(country_code) != 2 or not country_code.isalpha():
            raise ValueError("country_code must be a 2-letter ISO country code")

        if id_type.lower() not in ALLOWED_ID_TYPES:
            raise ValueError(f"id_type must be one of: {', '.join(sorted(ALLOWED_ID_TYPES))}")

        self.__country_code = country_code.upper()
        self.__id_type = id_type.lower()
        self.__id_number = id_number.strip()

    def __eq__(self, other: Any) -> bool:
        """
        Compares two PersonalId instances for equality
        """
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return False

    def as_str(self) -> str:
        """
        Returns the personal ID as a colon-separated string: "country_code:id_type:id_number"
        """
        return f"{self.__country_code}:{self.__id_type}:{self.__id_number}"

    def as_dict(self) -> dict[str, str]:
        """
        Returns the personal ID as a dictionary with keys: landCode, type, value
        """
        return {
            "landCode": self.__country_code,
            "type": self.__id_type,
            "value": self.__id_number,
        }

    def country_code(self) -> str:
        """
        Returns the country code of the personal ID
        """
        return self.__country_code

    def id_type(self) -> str:
        """
        Returns the ID type of the personal ID
        """
        return self.__id_type

    def id_number(self) -> str:
        """
        Returns the ID number of the personal ID
        """
        return self.__id_number

    @classmethod
    def from_str(cls, s: str) -> 'PersonalId':
        """
        Creates a PersonalId instance from a colon-separated string: "landCode:type:value"
        """
        parts = s.split(":")
        if len(parts) != 3:
            raise ValueError("Invalid personal ID format")

        return PersonalId(parts[0], parts[1], parts[2])

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> 'PersonalId':
        """
        Creates a PersonalId instance from a dictionary
        """
        try:
            return PersonalId(d["landCode"], d["type"], d["value"])
        except KeyError as e:
            raise ValueError(f"Missing key in personal ID dictionary: {e}")


class PersonalIdJSONEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, PersonalId):
            return obj.as_dict()
        return super().default(obj)
