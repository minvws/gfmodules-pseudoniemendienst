import uuid
from typing import Any

from sqlalchemy import Column, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import mapped_column, Mapped

from app.db.entities.base import Base


class OrganizationKey(Base):
    __tablename__ = "organization_key"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    scope = Column(JSONB, nullable=False, server_default="{}")
    key_data = Column(Text, nullable=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            # "organization_id": str(self.organization_id),
            "scope": self.scope,
            "key_data": self.key_data,
        }
