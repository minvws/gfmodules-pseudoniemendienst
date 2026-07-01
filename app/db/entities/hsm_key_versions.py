from datetime import datetime
import uuid
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Integer, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.entities.base import Base
from app.db.types.oin import OinType
from app.models.oin import Oin


class HsmKeyVersion(Base):
    """
    Represents a key version in the HSM.
    """

    __tablename__ = "hsm_key_version"
    __table_args__ = (UniqueConstraint("oin", "version"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    oin: Mapped[Oin] = mapped_column("oin", OinType(), nullable=False)
    version: Mapped[int] = mapped_column("version", Integer, nullable=False)
    from_dt: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    until_dt: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    removed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "version": self.version,
            "from_dt": self.from_dt,
            "until_dt": self.until_dt,
            "removed": self.removed,
        }
