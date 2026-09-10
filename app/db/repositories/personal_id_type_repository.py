from collections.abc import Sequence

from sqlalchemy import and_, select

from app.db.models.personal_id_type import PersonalIdTypeEntity
from app.db.repositories.repository_base import RepositoryBase
from app.enums.personal_id_type import PersonalIdType


class PersonalIdTypeRepository(RepositoryBase):
    def get_many(
        self,
        names: list[PersonalIdType] | list[str] | None = None,
    ) -> Sequence[PersonalIdTypeEntity]:
        conditions = []
        names_as_str = [str(n) for n in names] if names else []
        if names is not None:
            conditions.append(PersonalIdTypeEntity.name.in_(names_as_str))
        stmt = select(PersonalIdTypeEntity)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        return self.db_session.session.execute(stmt).scalars().all()
