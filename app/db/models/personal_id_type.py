from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import INTEGER, DateTime, Enum
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import Base
from app.enums.personal_id_type import PersonalIdType


class PersonalIdTypeEntity(Base):
    __tablename__ = "personal_id_types"
    __table_args__ = ({"schema": "admin"},)

    id: Mapped[uuid.UUID] = mapped_column(
        INTEGER,
        primary_key=True,
    )

    name: Mapped[PersonalIdType] = mapped_column(Enum(PersonalIdType), unique=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.now(tz=timezone.utc),
    )
