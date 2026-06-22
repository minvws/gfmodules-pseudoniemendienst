from typing import TypeVar, Dict, Any

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Base class for all database entities.
    """

    def to_dict(self) -> Dict[str, Any]:
        return {col.name: getattr(self, col.name) for col in self.__table__.columns}

    def __repr__(self) -> str:
        props = ", ".join(
            [f"{k}={self.__getattribute__(k)}" for k in self.__table__.columns.keys()]
        )
        return f"<{self.__class__.__name__}=({props})>"


TBase = TypeVar("TBase", bound=Base, covariant=True)
