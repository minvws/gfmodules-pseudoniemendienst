from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import UUID, ForeignKey
from sqlalchemy.orm import Mapped, Relationship, mapped_column, relationship

from app.db.models.base import (
    Base,
    WithTimestamps,
    WithUUID,
    client_certificates,
)

if TYPE_CHECKING:
    from app.db.models.certificate import CertificateEntity
    from app.db.models.organization import OrganizationEntity
    from app.db.models.organization_personal_id_type import ClientPersonalIdTypeEntity


class ClientEntity(Base, WithUUID, WithTimestamps):
    __tablename__ = "clients"
    __table_args__ = ({"schema": "admin"},)

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("admin.organizations.id"))

    organization: Mapped[OrganizationEntity] = Relationship(back_populates="clients")

    certificates: Mapped[list[CertificateEntity]] = Relationship(secondary=client_certificates)

    request_personal_id_types: Mapped[list[ClientPersonalIdTypeEntity]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            **WithUUID.to_dict(self),
            **WithTimestamps.to_dict(self),
            "organization_id": self.organization_id,
            "certificates": [c.id for c in self.certificates],
            "request_personal_id_types": [ra.personal_id_type.name for ra in self.request_personal_id_types],
        }
