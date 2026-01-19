import enum
from typing import Final, List

class AllowedFilesExtenions(str, enum.Enum):
    PEM = "pem"
    CRT = "crt"
    CERT = "cert"
    KEY = "key"

    @classmethod
    def from_list(cls, data: List[str]) -> List["AllowedFilesExtenions"]:
        return [cls(value) for value in data]


X509_FILE_EXTENSIONS: Final[List[AllowedFilesExtenions]] = AllowedFilesExtenions.from_list(["pem", "crt", "cert"])
