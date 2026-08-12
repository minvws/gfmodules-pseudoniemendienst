import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    INTEGER,
    UUID,
    Column,
    DateTime,
    ForeignKey,
    MetaData,
    Table,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class WithUUID:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
        }


class WithTimestamps:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.now(tz=timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.now(tz=timezone.utc),
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "deleted_at": self.deleted_at,
        }


admin_metadata_obj = MetaData(schema="admin")

client_certificates = Table(
    "client_certificates",
    Base.metadata,
    Column("client_id", UUID, ForeignKey("admin.clients.id"), primary_key=True),
    Column("certificate_id", UUID, ForeignKey("admin.certificates.id"), primary_key=True),
    schema="admin",
)

organization_receive_personal_id_types = Table(
    "organization_receive_personal_id_types",
    Base.metadata,
    Column("organization_id", UUID, ForeignKey("admin.organizations.id"), primary_key=True),
    Column("personal_id_type_id", INTEGER, ForeignKey("admin.personal_id_types.id"), primary_key=True),
    schema="admin",
)

organization_request_personal_id_types = Table(
    "organization_request_personal_id_types",
    Base.metadata,
    admin_metadata_obj,
    Column("organization_id", UUID, ForeignKey("admin.organizations.id"), primary_key=True),
    Column("personal_id_type_id", INTEGER, ForeignKey("admin.personal_id_types.id"), primary_key=True),
    schema="admin",
)
