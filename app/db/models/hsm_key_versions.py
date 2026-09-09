import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import UUID, Column, DateTime, ForeignKey, Integer
from sqlalchemy.orm import Mapped, Relationship, mapped_column

from app.db.models.base import Base
from app.db.models.organization import OrganizationEntity


class HsmKeyVersionEntity(Base):
    __tablename__ = "hsm_key_versions"
    __table_args__ = ({"schema": "prs"},)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID, ForeignKey(OrganizationEntity.id))
    version: Mapped[int] = mapped_column("version", Integer, nullable=False)
    from_dt: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    until_dt: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    organization: Mapped[OrganizationEntity] = Relationship(back_populates="hsm_key_versions")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "version": self.version,
            "from_dt": self.from_dt,
            "until_dt": self.until_dt,
            "removed_at": self.removed_at,
        }
