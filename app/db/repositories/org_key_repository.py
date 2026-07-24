import logging
import uuid
from typing import Optional, Sequence

from sqlalchemy import and_, delete, literal, or_, select, update
from sqlalchemy.dialects.postgresql.json import JSONB

from app.db.decorator import repository
from app.db.entities.organization_key import OrganizationKey
from app.db.repositories.repository_base import RepositoryBase

logger = logging.getLogger(__name__)


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

    def get_by_id(self, key_id: uuid.UUID) -> Optional[OrganizationKey]:
        """
        Fetches the key entry by its unique ID.
        """
        query = select(OrganizationKey).where(OrganizationKey.id == key_id)
        return self.db_session.execute(query).scalars().first()

    def get_by_org(self, org_id: uuid.UUID) -> Optional[Sequence[OrganizationKey]]:
        """
        Fetches all key entries for a given organization.
        """
        query = select(OrganizationKey).where(OrganizationKey.organization_id == org_id)
        return self.db_session.execute(query).scalars().all()

    def has_overlapping_scope(
        self,
        org_id: uuid.UUID,
        scope: list[str],
        exclude_key_id: Optional[uuid.UUID] = None,
    ) -> bool:
        """
        Returns whether any key entry in the organization overlaps with the given scope.
        """
        if "*" in scope:
            query = select(OrganizationKey.id).where(
                OrganizationKey.organization_id == org_id,
            )
        else:
            scope_conditions = [
                OrganizationKey.scope.contains(literal([scope_item], JSONB))
                for scope_item in scope
            ]
            scope_conditions.append(
                OrganizationKey.scope.contains(literal(["*"], JSONB))
            )

            query = select(OrganizationKey.id).where(
                OrganizationKey.organization_id == org_id,
                or_(*scope_conditions),
            )

        if exclude_key_id is not None:
            query = query.where(OrganizationKey.id != exclude_key_id)

        return self.db_session.execute(query.limit(1)).scalars().first() is not None

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
        organization_id: uuid.UUID,
        scope: list[str],
        key_data: str,
    ) -> Optional[OrganizationKey]:
        """
        Updates an existing key entry.
        """
        query = (
            update(OrganizationKey)
            .where(
                and_(
                    OrganizationKey.id == key_id,
                    OrganizationKey.organization_id == organization_id,
                )
            )
            .values(scope=scope, key_data=key_data)
            .returning(OrganizationKey)
        )
        entry: Optional[OrganizationKey] = (
            self.db_session.execute(query).scalars().one_or_none()
        )
        if entry is None:
            logger.warning(
                "key entry %s for organization_id %s does not exist",
                key_id,
                organization_id,
            )
            return None
        return entry

    def delete(self, key_id: uuid.UUID, organization_id: uuid.UUID) -> bool:
        """
        Deletes a key entry.
        """
        query = delete(OrganizationKey).where(OrganizationKey.id == key_id)
        query = query.where(OrganizationKey.organization_id == organization_id)

        result = self.db_session.execute(query.returning(OrganizationKey.id))
        return result.scalars().first() is not None
