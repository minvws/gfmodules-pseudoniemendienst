import uuid
from typing import Optional, Sequence

from app.db.decorator import repository
from app.db.entities.organization_key import OrganizationKey
from app.db.repositories.repository_base import RepositoryBase
from sqlalchemy.dialects.postgresql.json import JSONB
from sqlalchemy import delete, select, or_, literal, update


@repository(OrganizationKey)
class OrganizationKeyRepository(RepositoryBase):
    def get(self, org_id: uuid.UUID, scope: str) -> Optional[OrganizationKey]:
        """
        Fetches the key entry by organization and scope.
        If a key entry has scope *, it will match everything
        """
        query = (
            select(OrganizationKey)
            .where(OrganizationKey.organization_id == org_id)
            .where(
                or_(
                    OrganizationKey.scope.contains(literal([scope], JSONB)),
                    OrganizationKey.scope.contains(literal(["*"], JSONB)),
                )
            )
        )
        return self.db_session.execute(query).scalars().first()

    def get_by_org(self, org_id: uuid.UUID) -> Sequence[OrganizationKey]:
        """
        Fetches all key entries for a given organization.
        """
        query = select(OrganizationKey).where(OrganizationKey.organization_id == org_id)
        return self.db_session.execute(query).scalars().all()

    def create(
        self, org_id: uuid.UUID, scope: list[str], key_data: str, key_id: Optional[str]
    ) -> OrganizationKey:
        """
        Creates a new key entry.
        """
        entry = OrganizationKey(
            organization_id=org_id,
            scope=scope,
            key_data=key_data,
            key_id=key_id,
        )
        self.db_session.add(entry)
        self.db_session.flush()

        return entry

    def update(
        self,
        key_id: uuid.UUID,
        scope: list[str],
        key_data: str,
        organization_id: uuid.UUID,
    ) -> Optional[OrganizationKey]:
        """
        Updates an existing key entry by key id and organization id.
        """
        statement = (
            update(OrganizationKey)
            .where(
                OrganizationKey.id == key_id,
                OrganizationKey.organization_id == organization_id,
            )
            .values(scope=scope, key_data=key_data)
            .returning(OrganizationKey)
        )

        entry = self.db_session.execute(statement).scalars().one_or_none()
        return entry

    def delete(
        self,
        key_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> bool:
        """
        Removes a key entry by id for the specified organization.
        """
        statement = (
            delete(OrganizationKey)
            .where(
                OrganizationKey.id == key_id,
                OrganizationKey.organization_id == organization_id,
            )
            .returning(OrganizationKey.id)
        )
        deleted_id = self.db_session.execute(statement).scalars().first()
        if deleted_id is None:
            return False
        return True
