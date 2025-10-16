import logging
import uuid
from typing import Sequence, Optional

from sqlalchemy.dialects.postgresql.json import JSONB

from app.db.decorator import repository
from app.db.entities.organization_key import OrganizationKey
from app.db.repositories.repository_base import RepositoryBase
from sqlalchemy import select, or_, literal

logger = logging.getLogger(__name__)


@repository(OrganizationKey)
class OrganizationKeyRepository(RepositoryBase):

    def get(self, org_id: uuid.UUID, scope: str) -> Optional[OrganizationKey]:
        """
        Fetches the key entry by organization and scope.
        If a key entry has scope *, it will match everything
        """
        query = (select(OrganizationKey)
            .where(OrganizationKey.organization_id == org_id)
            .where(or_(
                OrganizationKey.scope.contains(literal([scope], JSONB)),
                OrganizationKey.scope.contains(literal(['*'], JSONB)),
            ))
        )
        return self.db_session.session.execute(query).scalars().first()

    def get_by_id(self, key_id: uuid.UUID) -> Optional[OrganizationKey]:
        """
        Fetches the key entry by its unique ID.
        """
        query = select(OrganizationKey).where(OrganizationKey.id == key_id)
        return self.db_session.session.execute(query).scalars().first()

    def get_by_org(self, org_id: uuid.UUID) -> Optional[Sequence[OrganizationKey]]:
        """
        Fetches all key entries for a given organization.
        """
        query = select(OrganizationKey).where(OrganizationKey.organization_id == org_id)
        return self.db_session.session.execute(query).scalars().all()

    def create(self, org_id: uuid.UUID, scope: list[str], key_data: str) -> OrganizationKey:
        """
        Creates a new key entry.
        """
        entry = OrganizationKey(
            organization_id=org_id,
            scope=scope,
            key_data=key_data,
        )
        self.db_session.session.add(entry)
        self.db_session.session.flush()

        return entry

    def update(self, key_id: uuid.UUID, scope: list[str], key_data: str) -> Optional[OrganizationKey]:
        """
        Updates an existing key entry.
        """
        entry = self.get_by_id(key_id)
        if entry is None:
            raise ValueError("Key entry not found")

        entry.scope = scope # type: ignore
        entry.key_data = key_data # type: ignore
        self.db_session.session.add(entry)
        return entry

    def delete_by_org(self, org_id: uuid.UUID) -> int:
        """
        Deletes all key entries for a given organization.
        """
        query = select(OrganizationKey).where(OrganizationKey.organization_id == org_id)
        entries = self.db_session.session.execute(query).scalars().all()
        count = len(entries)

        for entry in entries:
            self.db_session.session.delete(entry)

        return count
