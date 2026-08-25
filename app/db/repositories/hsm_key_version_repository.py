import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, func, insert, literal, or_, select, update
from sqlalchemy.orm import joinedload
from sqlalchemy.sql.elements import ColumnElement

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.repositories.repository_base import RepositoryBase
from app.models.oin import Oin

logger = logging.getLogger(__name__)


class HsmKeyVersionRepository(RepositoryBase):
    @staticmethod
    def _active_filter(at: datetime) -> ColumnElement[bool]:
        return and_(
            HsmKeyVersionEntity.removed_at.is_(None),
            HsmKeyVersionEntity.from_dt <= at,
            or_(
                HsmKeyVersionEntity.until_dt.is_(None),
                HsmKeyVersionEntity.until_dt > at,
            ),
        )

    @staticmethod
    def _expired_filter(at: datetime) -> ColumnElement[bool]:
        return and_(
            HsmKeyVersionEntity.removed_at.is_(None),
            HsmKeyVersionEntity.until_dt.is_not(None),
            HsmKeyVersionEntity.until_dt <= at,
        )

    def get_active_versions(
        self,
        at: datetime,
        organization_id: uuid.UUID,
    ) -> list[HsmKeyVersionEntity]:
        """
        Returns all key versions that are active at the given moment, i.e. not
        removed, already started (from_dt <= at) and not yet ended (until_dt is
        unset or still in the future), restricted to organization_id.
        """
        query = (
            select(HsmKeyVersionEntity)
            .where(
                HsmKeyVersionEntity.organization_id == organization_id,
                HsmKeyVersionRepository._active_filter(at),
            )
            .order_by(HsmKeyVersionEntity.version)
        )
        return list(self.db_session.execute(query).scalars().all())

    def get_active_versions_by_organization_oin(
        self,
        at: datetime,
        organization_oin: Oin,
    ) -> list[HsmKeyVersionEntity]:
        """
        Returns all active key versions for the organization with the provided OIN.
        """
        query = (
            select(HsmKeyVersionEntity)
            .where(
                HsmKeyVersionEntity.organization_id == organization_oin,
                HsmKeyVersionRepository._active_filter(at),
            )
            .order_by(HsmKeyVersionEntity.version)
        )
        return list(self.db_session.execute(query).scalars().all())

    def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> list[HsmKeyVersionEntity]:
        """
        Returns all key versions for the given organization UUID, regardless of
        date or removed state, ordered by version number.
        """
        query = (
            select(HsmKeyVersionEntity)
            .where(HsmKeyVersionEntity.organization_id == organization_id)
            .order_by(HsmKeyVersionEntity.version)
        )
        return list(self.db_session.execute(query).scalars().all())

    def get_expired_versions(self, at: datetime) -> list[HsmKeyVersionEntity]:
        """
        Returns all key versions that have passed their end date (until_dt is set
        and in the past) but have not been removed yet.
        """
        query = (
            select(HsmKeyVersionEntity)
            .where(
                HsmKeyVersionRepository._expired_filter(at),
            )
            .options(joinedload(HsmKeyVersionEntity.organization))
        )
        return list(self.db_session.execute(query).scalars().all())

    def get_active_or_create_version_numbers_by_organization_id(
        self,
        organization_id: uuid.UUID,
        at: datetime,
    ) -> list[int]:
        """
        Returns active version numbers at `at` for the organization. When no
        active version exists, atomically creates a new one and returns its
        version number.
        """
        active_versions = (
            select(HsmKeyVersionEntity.version)
            .where(
                HsmKeyVersionEntity.organization_id == organization_id,
                HsmKeyVersionRepository._active_filter(at),
            )
            .order_by(HsmKeyVersionEntity.version)
            .cte("active_versions")
        )

        next_version = (
            select(func.max(HsmKeyVersionEntity.version) + 1)
            .where(HsmKeyVersionEntity.organization_id == organization_id)
            .scalar_subquery()
        )

        created_versions = (
            insert(HsmKeyVersionEntity)
            .from_select(
                [
                    HsmKeyVersionEntity.id,
                    HsmKeyVersionEntity.organization_id,
                    HsmKeyVersionEntity.version,
                    HsmKeyVersionEntity.from_dt,
                    HsmKeyVersionEntity.until_dt,
                    HsmKeyVersionEntity.removed_at,
                ],
                select(
                    literal(uuid.uuid4()),
                    literal(organization_id),
                    func.coalesce(next_version, 1),
                    literal(at),
                    literal(None),
                    literal(False),
                ).where(~select(active_versions.c.version).limit(1).exists()),
            )
            .returning(HsmKeyVersionEntity.version)
            .cte("created_version")
        )

        rows = (
            select(active_versions.c.version)
            .union_all(select(created_versions.c.version))
            .order_by(active_versions.c.version)
        )

        return list(
            self.db_session.execute(
                select(HsmKeyVersionEntity.version).from_statement(rows)
            )
            .scalars()
            .all()
        )

    def create(
        self,
        organization_id: uuid.UUID,
        from_dt: datetime,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersionEntity:
        """
        Inserts a new key version entry for the given organization id.
        """
        next_version = (
            select(func.max(HsmKeyVersionEntity.version) + 1)
            .where(HsmKeyVersionEntity.organization_id == organization_id)
            .scalar_subquery()
        )

        statement = (
            insert(HsmKeyVersionEntity)
            .values(
                organization_id=organization_id,
                version=func.coalesce(next_version, 1),
                from_dt=from_dt,
                until_dt=until_dt,
            )
            .returning(HsmKeyVersionEntity)
        )

        entry: HsmKeyVersionEntity = self.db_session.execute(statement).scalars().one()
        logger.info("created hsm key version for organization %s", organization_id)
        return entry

    def get_by_id(self, version_id: uuid.UUID) -> HsmKeyVersionEntity | None:
        """
        Fetches a single key version by its unique ID.
        """
        query = select(HsmKeyVersionEntity).where(HsmKeyVersionEntity.id == version_id)
        return self.db_session.execute(query).scalars().first()

    def update(
        self,
        version_id: uuid.UUID,
        organization_id: uuid.UUID,
        until_dt: datetime | None,
    ) -> HsmKeyVersionEntity | None:
        """
        Updates the end date of an existing active key version for the
        organization identified by organization_id.
        """
        statement = (
            update(HsmKeyVersionEntity)
            .where(
                and_(
                    HsmKeyVersionEntity.id == version_id,
                    HsmKeyVersionEntity.removed_at.is_(None),
                    HsmKeyVersionEntity.organization_id == organization_id,
                )
            )
            .values(until_dt=until_dt)
            .returning(HsmKeyVersionEntity)
        )

        # SQLAlchemy currently types this result as `Any`, so we annotate it for
        # mypy. Because we use `.returning(HsmKeyVersionEntity)`, runtime rows are
        # mapped back to `HsmKeyVersionEntity` (or `None` when no row matches).
        entry: HsmKeyVersionEntity | None = (
            self.db_session.execute(statement).scalars().one_or_none()
        )
        if entry is None:
            logger.warning(
                "hsm key version %s for organization_id %s does not exist",
                version_id,
                organization_id,
            )
            return None

        logger.info(
            "updated hsm key version %s for organization_id %s",
            version_id,
            organization_id,
        )
        return entry

    def mark_removed(
        self,
        version_id: uuid.UUID,
    ) -> HsmKeyVersionEntity | None:
        """
        Flags an existing key version as removed, leaving its dates untouched.
        Returns `None` when no version exists for that ID.
        """
        now = datetime.now(timezone.utc)
        statement = (
            update(HsmKeyVersionEntity)
            .where(
                and_(
                    HsmKeyVersionEntity.id == version_id,
                    HsmKeyVersionEntity.removed_at.is_(None),
                )
            )
            .values(removed_at=now)
            .returning(HsmKeyVersionEntity)
        )

        # SQLAlchemy currently types this result as `Any`, so we annotate it for
        # mypy. Because we use `.returning(HsmKeyVersionEntity)`, runtime rows are
        # mapped back to `HsmKeyVersionEntity` (or `None` when no row matches).
        entry: HsmKeyVersionEntity | None = (
            self.db_session.execute(statement).scalars().one_or_none()
        )
        if entry is None:
            logger.warning("hsm key version %s does not exist", version_id)
            return None

        logger.info("marked hsm key version %s as removed", version_id)

        return entry
