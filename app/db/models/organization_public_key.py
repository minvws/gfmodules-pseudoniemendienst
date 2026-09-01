from app.db.models.base import Base
import uuid
from typing import TYPE_CHECKING, Any

from pyoprf import List
from sqlalchemy import ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, Relationship

if TYPE_CHECKING:
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

    organization: Mapped[OrganizationEntity] = Relationship(
        back_populates="public_keys"
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
