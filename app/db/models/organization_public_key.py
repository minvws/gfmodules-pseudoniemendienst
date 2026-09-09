import uuid
from typing import Any

from pyoprf import List
from sqlalchemy import UUID, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base
from app.db.models.organization import OrganizationEntity


class OrganizationPublicKeyEntity(Base):
    """
    Represents a key associated with an organization in the database.
    """

    __tablename__ = "organization_public_keys"
    __table_args__: tuple[Any, ...] = ({"schema": "prs"},)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID, ForeignKey("admin.organizations.id")
    )

    organization: Mapped[OrganizationEntity] = relationship(
        "OrganizationEntity", back_populates="public_keys"
    )

    domains: Mapped[List[str]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )

    jwk: Mapped[dict[str, str]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            # We omit organization_id since this is an internal detail.
            "domains": self.domains,
            "jwk": self.jwk,
        }
