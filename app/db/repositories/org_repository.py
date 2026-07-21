import logging
from typing import Optional

from sqlalchemy import select

from app.db.decorator import repository
from app.db.entities.organization import Organization
from app.db.repositories.repository_base import RepositoryBase
from app.models.oin import Oin

logger = logging.getLogger(__name__)


@repository(Organization)
class OrgRepository(RepositoryBase):
    def get_by_oin(self, oin: Oin) -> Optional[Organization]:
        """
        Fetches the organization by its unique ID.
        """
        query = select(Organization).where(Organization.oin == oin)
        return self.db_session.execute(query).scalars().first()

    def create(self, oin: Oin, name: str, max_usage_level: str) -> Organization:
        """
        Creates a new org entry.
        """
        entry = Organization(
            oin=oin,
            name=name,
            max_rid_usage=max_usage_level,
        )
        self.db_session.add(entry)
        self.db_session.flush()

        logger.info("created organization with OIN %s and name %r", oin.value, name)
        return entry
