from datetime import datetime
import uuid
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.entities.base import Base
from app.db.entities.organization import Organization
from app.models.oin import Oin


class HsmKeyVersion(Base):
    """
    Represents a key version in the HSM.
    """

    __tablename__ = "hsm_key_version"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organization.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column("version", Integer, nullable=False)
    from_dt: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    until_dt: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    removed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )

    organization: Mapped[Organization] = relationship("Organization")

    @property
    def oin(self) -> Oin:
        return self.organization.oin

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "oin": self.oin.value,
            "version": self.version,
            "from_dt": self.from_dt,
            "until_dt": self.until_dt,
            "removed": self.removed,
        }
