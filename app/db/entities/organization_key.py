import uuid
from typing import Any

from sqlalchemy import Column, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import mapped_column, Mapped, relationship

from app.db.entities.base import Base


class OrganizationKey(Base):
    __tablename__ = "organization_key"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organization.id", ondelete="CASCADE"), nullable=False)
    scope = Column(JSONB, nullable=False, server_default="{}")
    key_data = Column(Text, nullable=False)

    organization = relationship("Organization", back_populates="keys")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            # We omit organization_id since this is an internal detail.
            "scope": self.scope,
            "key_data": self.key_data,
        }
