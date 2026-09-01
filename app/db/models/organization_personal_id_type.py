from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import UUID, DateTime, ForeignKey, ForeignKeyConstraint, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models import ClientEntity
from app.db.models.base import Base
from app.db.models.personal_id_type import PersonalIdTypeEntity


class ClientPersonalIdTypeEntity(Base):
    __tablename__ = "client_request_personal_id_types"
    __table_args__: tuple[Any, ...] = (
        ForeignKeyConstraint(
            ["organization_id", "personal_id_type_id"],
            [
                "admin.organization_request_personal_id_types.organization_id",
                "admin.organization_request_personal_id_types.personal_id_type_id",
            ],
        ),
        {"schema": "admin"},
    )

    client_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("admin.clients.id"), primary_key=True)

    personal_id_type_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("admin.personal_id_types.id"), primary_key=True
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID, ForeignKey("admin.organizations.id"), primary_key=True)

    client: Mapped[ClientEntity] = relationship(back_populates="request_personal_id_types")

    personal_id_type: Mapped[PersonalIdTypeEntity] = relationship()

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.now(tz=timezone.utc),
    )
