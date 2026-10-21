from dataclasses import asdict, dataclass
from typing import Self

from app.models.auth.context import AuthContext
from app.models.oin import Oin


@dataclass(frozen=True)
class ExchangeAudit:
    handelende_oin: str
    namens_oin: str
    doel_oin: str

    @classmethod
    def from_auth(cls, auth: AuthContext, recipient: Oin) -> Self:
        return cls(
            handelende_oin=str(auth.claims.client_organization_id),
            namens_oin=str(auth.claims.organization_id),
            doel_oin=str(recipient),
        )

    def fields(self) -> dict[str, str]:
        return asdict(self)
