import uuid
from typing import Any

from sqlalchemy import UUID, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base, WithTimestamps


class CertificateEntity(Base, WithTimestamps):
    __tablename__ = "certificates"
    __table_args__ = ({"schema": "admin"},)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    organization_identifier: Mapped[str] = mapped_column(String)

    domain: Mapped[str] = mapped_column(String)

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("admin.organizations.id"))

    def to_dict(self) -> dict[str, Any]:
        return {
            **WithTimestamps.to_dict(self),
            "id": self.id,
            "organization_identifier": self.organization_identifier,
            "domain": self.domain,
            "organization_id": self.organization_id,
        }
