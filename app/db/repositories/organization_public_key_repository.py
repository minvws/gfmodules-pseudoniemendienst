import logging
import uuid

from sqlalchemy import delete, select

from app.db.models.organization_public_key import OrganizationPublicKeyEntity
from app.db.repositories.repository_base import RepositoryBase

logger = logging.getLogger(__name__)


class OrganizationPublicKeyRepository(RepositoryBase):
    def get_by_id(self, key_id: uuid.UUID) -> OrganizationPublicKeyEntity | None:
        """
        Fetches the key entry by its unique ID.
        """
        query = select(OrganizationPublicKeyEntity).where(
            OrganizationPublicKeyEntity.id == key_id
        )
        return self.db_session.execute(query).scalars().first()

    def create(
        self, organization_public_key: OrganizationPublicKeyEntity
    ) -> OrganizationPublicKeyEntity:
        """
        Creates a new key entry.
        """
        self.db_session.add(organization_public_key)
        return organization_public_key

    def delete(self, key_id: uuid.UUID, organization_id: uuid.UUID) -> bool:
        """
        Deletes a key entry.
        """
        query = delete(OrganizationPublicKeyEntity).where(
            OrganizationPublicKeyEntity.id == key_id
        )
        query = query.where(
            OrganizationPublicKeyEntity.organization_id == organization_id
        )

        result = self.db_session.execute(
            query.returning(OrganizationPublicKeyEntity.id)
        )
        return result.scalars().first() is not None
