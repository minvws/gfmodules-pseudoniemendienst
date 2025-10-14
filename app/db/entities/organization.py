import uuid
from typing import Any

from sqlalchemy import Column, String, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.db.entities.base import Base


class Organization(Base):
    __tablename__ = "organization"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ura = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    max_rid_usage = Column(String, nullable=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "ura": self.ura,
            "name": self.name,
            "max_rid_usage": self.max_rid_usage,
        }
