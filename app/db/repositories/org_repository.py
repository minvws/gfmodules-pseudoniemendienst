import logging
import uuid
from typing import Optional

from app.db.decorator import repository
from app.db.entities.organization import Organization
from app.db.repositories.repository_base import RepositoryBase
from sqlalchemy import select

logger = logging.getLogger(__name__)


@repository(Organization)
class OrgRepository(RepositoryBase):
    def get_by_oin(self, oin: str) -> Optional[Organization]:
        """
        Fetches the organization by its unique ID.
        """
        query = select(Organization).where(Organization.oin == oin)
        return self.db_session.execute(query).scalars().first()

    def create(self, oin: str, name: str, max_usage_level: str) -> Organization:
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

        logger.info("created organization with OIN %s and name %r", oin, name)
        return entry

    def update(
        self, org_id: uuid.UUID, name: str, max_usage_level: str
    ) -> Optional[Organization]:
        """
        Updates an existing key entry.
        """
        org = self.get_by_id(org_id)
        if org is None:
            logger.error(f"organization with ID {org_id} does not exist")
            raise ValueError("Organization not found")

        org.name = name
        org.max_rid_usage = max_usage_level
        self.db_session.add(org)
        return org

    def delete(self, org_id: uuid.UUID) -> bool:
        """
        Deletes an organization by its unique ID.
        """
        org = self.get_by_id(org_id)
        if org is None:
            logger.error("organization with ID %s does not exist", org_id)
            return False

        self.db_session.delete(org)
        return True

    def get_by_id(self, org_id: uuid.UUID) -> Optional[Organization]:
        """
        Fetches the organization by its unique ID.
        """
        query = select(Organization).where(Organization.id == org_id)
        return self.db_session.execute(query).scalars().first()
