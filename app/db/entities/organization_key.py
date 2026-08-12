import json
from jwcrypto.jwk import JWK
from app.models.oin import Oin
from app.db.types.oin import OinType
import uuid
from typing import TYPE_CHECKING, Any
from pyoprf import List
from sqlalchemy import ForeignKey, Text, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.entities.base import Base


class OrganizationPublicKey(Base):
    __tablename__ = "organization_public_keys"
    __table_args__ = {"schema": "prs"}

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[Oin] = mapped_column(
        "organization_id",
        OinType(),
        nullable=False,
    )
    domain: Mapped[str] = mapped_column(
        "domain", String, nullable=False, server_default="{}"
    )
    jwk: Mapped[str] = mapped_column("jwk", Text, nullable=False)
    kid: Mapped[str] = mapped_column("kid", Text, nullable=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "domain": self.domain,
            "jwk": JWK(**json.loads(self.jwk)),
            "kid": self.kid,
        }
