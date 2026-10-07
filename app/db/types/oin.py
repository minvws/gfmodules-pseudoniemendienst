from typing import Any

from sqlalchemy import String
from sqlalchemy.types import TypeDecorator

from app.models.oin import Oin


class OinType(TypeDecorator[Oin]):
    """Maps a column to the OIN value object and stores it as text."""

    impl = String
    cache_ok = True
    python_type = Oin

    def process_bind_param(self, value: Any, _dialect: Any) -> str | None:
        if value is None:
            return None

        if isinstance(value, Oin):
            return value.value

        return str(value)

    def process_result_value(self, value: Any, _dialect: Any) -> Oin | None:
        if value is None:
            return None

        return Oin(value)
