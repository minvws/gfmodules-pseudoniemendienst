import uuid
from typing import Any

from sqlalchemy import Column, String, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.db.entities.base import Base


class KeyEntry(Base):
    __tablename__ = "key_entry"

    entry_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization = Column(String, nullable=False)
    scope = Column(JSONB, nullable=False, server_default="{}")
    key = Column(Text, nullable=False)
    max_rid_usage = Column(String, nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": str(self.entry_id),
            "organization": self.organization,
            "scope": self.scope,
            "pub_key": self.key,
            "max_rid_usage": self.max_rid_usage,
        }
