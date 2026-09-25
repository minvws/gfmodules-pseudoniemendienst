from sqlalchemy import and_, select

from app.db.models.organization import OrganizationEntity
from app.db.repositories.repository_base import RepositoryBase
from app.exceptions import OrganizationNotRegisteredError
from app.models.oin import Oin


class OrganizationRepository(RepositoryBase):
    def get_one_by_external_id(self, external_id: Oin) -> OrganizationEntity | None:
        """
        Because of the unique index on (external_id and deleted_at is None)
        we can assume that there will at most one match
        """
        stmt = select(OrganizationEntity).where(
            and_(
                OrganizationEntity.external_id == external_id,
                OrganizationEntity.deleted_at.is_(None),
            )
        )
        return self.db_session.execute(stmt).scalar()

    def get_registered(self, external_id: Oin) -> OrganizationEntity:
        """
        The organization the caller acts for. The proxy verified its identity,
        so an organization that is missing here is one the PRS does not serve.
        """
        org = self.get_one_by_external_id(external_id)
        if org is None:
            raise OrganizationNotRegisteredError()
        return org
