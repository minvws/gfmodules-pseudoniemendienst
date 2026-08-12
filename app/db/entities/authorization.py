from app.models.oin import Oin
from app.db.types.oin import OinType
import uuid
from typing import Any
from sqlalchemy import String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.entities.base import Base


class Authorization(Base):
    __tablename__ = "authorizations"
    __table_args__ = {"schema": "prs"}

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[Oin] = mapped_column(
        "organization_id",
        OinType(),
        nullable=False,
    )
    action: Mapped[str] = mapped_column("action", String, nullable=False)

    object: Mapped[str] = mapped_column("object", String, nullable=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "organization_id": self.organization_id,
            "action": self.action,
            "object": self.object,
        }
