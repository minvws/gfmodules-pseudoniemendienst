import uuid
from typing import Any

from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.entities.base import Base


class Organization(Base):
    """
    Represents an organization in the database.
    """
    __tablename__ = "organization"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ura = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    max_rid_usage = Column(String, nullable=False)

    keys = relationship(
        "OrganizationKey",
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ura": self.ura,
            "name": self.name,
            "max_rid_usage": self.max_rid_usage,
        }
