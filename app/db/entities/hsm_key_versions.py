import uuid
from typing import Any

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.entities.base import Base


class HsmKeyVersion(Base):
    """
    Represents a key version in the HSM.
    """

    __tablename__ = "hsm_key_version"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ura = Column(String, nullable=False)
    version = Column(Integer, nullable=False)
    from_dt = Column(DateTime(timezone=True), nullable=False)
    until_dt = Column(DateTime(timezone=True), nullable=True)
    removed = Column(Boolean, nullable=False, server_default="false")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "ura": self.ura,
            "version": self.version,
            "from_dt": self.from_dt,
            "until_dt": self.until_dt,
            "removed": self.removed,
        }
