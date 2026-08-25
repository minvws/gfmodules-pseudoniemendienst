import logging
import uuid

from sqlalchemy import and_, delete, literal, or_, select, update
from sqlalchemy.dialects.postgresql.json import JSONB

from app.db.decorator import repository
from app.db.entities.organization_key import OrganizationPublicKey
from app.db.repositories.repository_base import RepositoryBase

logger = logging.getLogger(__name__)


@repository(OrganizationPublicKey)
class OrganizationPublicKeyRepository(RepositoryBase):
    def get(self, id: uuid.UUID) -> OrganizationPublicKey | None:
        query = select(OrganizationPublicKey).where(OrganizationPublicKey.id == id)
        return self.db_session.execute(query).scalars().first()

    def get_by_id(self, key_id: uuid.UUID) -> OrganizationPublicKey | None:
        """
        Fetches the key entry by its unique ID.
        """
        query = select(OrganizationPublicKey).where(OrganizationPublicKey.id == key_id)
        return self.db_session.execute(query).scalars().first()

    def get_by_org(self, org_id: uuid.UUID) -> list[OrganizationPublicKey]:
        """
        Fetches key entrie for a given organization id and matching domain.
        """
        query = select(OrganizationPublicKey).where(
            OrganizationPublicKey.organization_id == org_id
        )
        return list(self.db_session.execute(query).scalars())

    def get_by_org_and_domain(
        self, org_id: uuid.UUID, domain: str
    ) -> OrganizationPublicKey | None:
        """
        Fetches key entrie for a given organization id and matching domain.
        """
        query = select(OrganizationPublicKey).where(
            OrganizationPublicKey.organization_id == org_id
            and OrganizationPublicKey.domain == domain
        )
        return self.db_session.execute(query).scalars().first()

    def has_overlapping_scope(
        self,
        org_id: uuid.UUID,
        scope: list[str],
        exclude_key_id: uuid.UUID | None = None,
    ) -> bool:
        """
        Returns whether any key entry in the organization overlaps with the given scope.
        """
        if "*" in scope:
            query = select(OrganizationPublicKey.id).where(
                OrganizationPublicKey.organization_id == org_id,
            )
        else:
            scope_conditions = [
                OrganizationPublicKey.scope.contains(literal([scope_item], JSONB))
                for scope_item in scope
            ]
            scope_conditions.append(
                OrganizationPublicKey.scope.contains(literal(["*"], JSONB))
            )

            query = select(OrganizationPublicKey.id).where(
                OrganizationPublicKey.organization_id == org_id,
                or_(*scope_conditions),
            )

        if exclude_key_id is not None:
            query = query.where(OrganizationPublicKey.id != exclude_key_id)

        return self.db_session.execute(query.limit(1)).scalars().first() is not None

    def create(
        self, organization_public_key: OrganizationPublicKey
    ) -> OrganizationPublicKey:
        """
        Creates a new key entry.
        """
        self.db_session.add(organization_public_key)
        return organization_public_key

    def update(
        self,
        id: uuid.UUID,
        organization_id: uuid.UUID,
        scope: list[str],
        key_data: str,
        key_id: str | None,
    ) -> OrganizationPublicKey | None:
        """
        Updates an existing key entry.
        """
        query = (
            update(OrganizationPublicKey)
            .where(
                and_(
                    OrganizationPublicKey.id == id,
                    OrganizationPublicKey.organization_id == organization_id,
                )
            )
            .values(scope=scope, key_data=key_data, key_id=key_id)
            .returning(OrganizationPublicKey)
        )

        # SQLAlchemy currently types this result as `Any`, so we annotate it for
        # mypy. Because we use `.returning(OrganizationPublicKey)`, runtime rows are
        # mapped back to `OrganizationPublicKey` (or `None` when no row matches).
        entry: OrganizationPublicKey | None = (
            self.db_session.execute(query).scalars().one_or_none()
        )
        if entry is None:
            logger.warning(
                "key entry %s for organization_id %s does not exist",
                id,
                organization_id,
            )
            return None
        return entry

    def delete(self, key_id: uuid.UUID, organization_id: uuid.UUID) -> bool:
        """
        Deletes a key entry.
        """
        query = delete(OrganizationPublicKey).where(OrganizationPublicKey.id == key_id)
        query = query.where(OrganizationPublicKey.organization_id == organization_id)

        result = self.db_session.execute(query.returning(OrganizationPublicKey.id))
        return result.scalars().first() is not None
