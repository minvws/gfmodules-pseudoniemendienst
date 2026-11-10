from dataclasses import asdict, dataclass
from typing import Self

from app.models.auth.context import AuthContext
from app.models.oin import Oin


@dataclass(frozen=True)
class ExchangeAudit:
    acting_organization_identifier: str
    represented_organization_identifier: str
    recipient_organization_identifier: str

    @classmethod
    def from_auth(cls, auth: AuthContext, recipient: Oin) -> Self:
        return cls(
            acting_organization_identifier=str(auth.claims.client_organization_id),
            represented_organization_identifier=str(auth.claims.organization_id),
            recipient_organization_identifier=str(recipient),
        )

    def fields(self) -> dict[str, str]:
        return asdict(self)
