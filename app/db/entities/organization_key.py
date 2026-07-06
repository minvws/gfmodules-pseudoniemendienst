import uuid
from typing import Any, TYPE_CHECKING

from pyoprf import List
from sqlalchemy import Text, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import mapped_column, Mapped, relationship
from app.db.entities.base import Base

if TYPE_CHECKING:
    from app.db.entities.organization import Organization


class OrganizationKey(Base):
    """
    Represents a key associated with an organization in the database.
    """

    __tablename__ = "organization_key"
    __table_args__ = (UniqueConstraint("organization_id", "scope"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organization.id", ondelete="CASCADE"),
        nullable=False,
    )
    scope: Mapped[List[str]] = mapped_column(
        "scope", JSONB, nullable=False, server_default="{}"
    )
    key_data: Mapped[str] = mapped_column("key_data", Text, nullable=False)
    key_id: Mapped[str | None] = mapped_column("key_id", Text, nullable=True)

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="keys"
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            # We omit organization_id since this is an internal detail.
            "scope": self.scope,
            "key_data": self.key_data,
            "key_id": self.key_id or "",
        }
