import logging
import uuid
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import and_, func, insert, literal, or_, select, update
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.orm import joinedload
from app.db.decorator import repository
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.entities.organization import Organization
from app.db.repositories.repository_base import RepositoryBase
from app.models.oin import Oin

logger = logging.getLogger(__name__)


@repository(HsmKeyVersion)
class HsmKeyVersionRepository(RepositoryBase):
    @staticmethod
    def _active_filter(at: datetime) -> ColumnElement[bool]:
        return and_(
            HsmKeyVersion.removed.is_(False),
            HsmKeyVersion.from_dt <= at,
            or_(HsmKeyVersion.until_dt.is_(None), HsmKeyVersion.until_dt > at),
        )

    @staticmethod
    def _expired_filter(at: datetime) -> ColumnElement[bool]:
        return and_(
            HsmKeyVersion.removed.is_(False),
            HsmKeyVersion.until_dt.is_not(None),
            HsmKeyVersion.until_dt <= at,
        )

    def get_active_versions(
        self,
        at: datetime,
        organization_id: uuid.UUID,
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that are active at the given moment, i.e. not
        removed, already started (from_dt <= at) and not yet ended (until_dt is
        unset or still in the future), restricted to organization_id.
        """
        query = (
            select(HsmKeyVersion)
            .where(
                HsmKeyVersion.organization_id == organization_id,
                HsmKeyVersionRepository._active_filter(at),
            )
            .order_by(HsmKeyVersion.version)
        )
        return self.db_session.execute(query).scalars().all()

    def get_active_versions_by_organization_oin(
        self,
        at: datetime,
        organization_oin: Oin,
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all active key versions for the organization with the provided OIN.
        """
        query = (
            select(HsmKeyVersion)
            .join(HsmKeyVersion.organization)
            .where(
                Organization.oin == organization_oin,
                HsmKeyVersionRepository._active_filter(at),
            )
            .order_by(HsmKeyVersion.version)
        )
        return self.db_session.execute(query).scalars().all()

    def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions for the given organization UUID, regardless of
        date or removed state, ordered by version number.
        """
        query = (
            select(HsmKeyVersion)
            .where(HsmKeyVersion.organization_id == organization_id)
            .order_by(HsmKeyVersion.version)
        )
        return self.db_session.execute(query).scalars().all()

    def get_expired_versions(self, at: datetime) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that have passed their end date (until_dt is set
        and in the past) but have not been removed yet.
        """
        query = (
            select(HsmKeyVersion)
            .where(
                HsmKeyVersionRepository._expired_filter(at),
            )
            .options(joinedload(HsmKeyVersion.organization))
        )
        return self.db_session.execute(query).scalars().all()

    def get_active_or_create_version_numbers_by_organization_id(
        self,
        organization_id: uuid.UUID,
        at: datetime,
    ) -> Sequence[int]:
        """
        Returns active version numbers at `at` for the organization. When no
        active version exists, atomically creates a new one and returns its
        version number.
        """
        active_versions = (
            select(HsmKeyVersion.version)
            .where(
                HsmKeyVersion.organization_id == organization_id,
                HsmKeyVersionRepository._active_filter(at),
            )
            .order_by(HsmKeyVersion.version)
            .cte("active_versions")
        )

        next_version = (
            select(func.max(HsmKeyVersion.version) + 1)
            .where(HsmKeyVersion.organization_id == organization_id)
            .scalar_subquery()
        )

        created_versions = (
            insert(HsmKeyVersion)
            .from_select(
                [
                    HsmKeyVersion.id,
                    HsmKeyVersion.organization_id,
                    HsmKeyVersion.version,
                    HsmKeyVersion.from_dt,
                    HsmKeyVersion.until_dt,
                    HsmKeyVersion.removed,
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
            .returning(HsmKeyVersion.version)
            .cte("created_version")
        )

        rows = (
            select(active_versions.c.version)
            .union_all(select(created_versions.c.version))
            .order_by(active_versions.c.version)
        )

        return (
            self.db_session.execute(select(HsmKeyVersion.version).from_statement(rows))
            .scalars()
            .all()
        )

    def create(
        self,
        organization_id: uuid.UUID,
        from_dt: datetime,
        until_dt: Optional[datetime] = None,
    ) -> HsmKeyVersion:
        """
        Inserts a new key version entry for the given organization id.
        """
        next_version = (
            select(func.max(HsmKeyVersion.version) + 1)
            .where(HsmKeyVersion.organization_id == organization_id)
            .scalar_subquery()
        )

        statement = (
            insert(HsmKeyVersion)
            .values(
                organization_id=organization_id,
                version=func.coalesce(next_version, 1),
                from_dt=from_dt,
                until_dt=until_dt,
            )
            .returning(HsmKeyVersion)
        )

        entry: HsmKeyVersion = self.db_session.execute(statement).scalars().one()
        logger.info("created hsm key version for organization %s", organization_id)
        return entry

    def get_by_id(self, version_id: uuid.UUID) -> Optional[HsmKeyVersion]:
        """
        Fetches a single key version by its unique ID.
        """
        query = select(HsmKeyVersion).where(HsmKeyVersion.id == version_id)
        return self.db_session.execute(query).scalars().first()

    def update(
        self,
        version_id: uuid.UUID,
        organization_id: uuid.UUID,
        until_dt: Optional[datetime],
    ) -> Optional[HsmKeyVersion]:
        """
        Updates the end date of an existing active key version for the
        organization identified by organization_id.
        """
        statement = (
            update(HsmKeyVersion)
            .where(
                and_(
                    HsmKeyVersion.id == version_id,
                    HsmKeyVersion.removed.is_(False),
                    HsmKeyVersion.organization_id == organization_id,
                )
            )
            .values(until_dt=until_dt)
            .returning(HsmKeyVersion)
        )

        entry: Optional[HsmKeyVersion] = (
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
    ) -> Optional[HsmKeyVersion]:
        """
        Flags an existing key version as removed, leaving its dates untouched.
        Returns ``None`` when no version exists for that ID.
        """
        statement = (
            update(HsmKeyVersion)
            .where(
                and_(
                    HsmKeyVersion.id == version_id,
                    HsmKeyVersion.removed.is_(False),
                )
            )
            .values(removed=True)
            .returning(HsmKeyVersion)
        )

        entry: Optional[HsmKeyVersion] = (
            self.db_session.execute(statement).scalars().one_or_none()
        )
        if entry is None:
            logger.warning("hsm key version %s does not exist", version_id)
            return None

        logger.info("marked hsm key version %s as removed", version_id)

        return entry
