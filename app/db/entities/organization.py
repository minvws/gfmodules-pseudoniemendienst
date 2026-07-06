import uuid
from typing import Any, List, Optional, TYPE_CHECKING

from app.db.types.oin import OinType
from app.models.oin import Oin
from sqlalchemy import String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.entities.base import Base

if TYPE_CHECKING:
    from app.db.entities.organization_key import OrganizationKey
    from app.db.entities.hsm_key_versions import HsmKeyVersion


class Organization(Base):
    """
    Represents an organization in the database.
    """

    __tablename__ = "organization"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    oin: Mapped[Oin] = mapped_column("oin", OinType(), unique=True)
    name: Mapped[str] = mapped_column("name", String)
    max_rid_usage: Mapped[str] = mapped_column("max_rid_usage", String)

    keys: Mapped[Optional[List["OrganizationKey"]]] = relationship(
        "OrganizationKey",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    hsm_key_versions: Mapped[Optional[List["HsmKeyVersion"]]] = relationship(
        "HsmKeyVersion",
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "oin": self.oin.value,
            "name": self.name,
            "max_rid_usage": self.max_rid_usage,
        }
