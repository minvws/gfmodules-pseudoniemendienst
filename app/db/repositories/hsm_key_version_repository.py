import logging
import uuid
from datetime import datetime

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import joinedload
from sqlalchemy.sql.elements import ColumnElement

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.repositories.repository_base import RepositoryBase
from app.utils.datetime import now_utc

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

    def get_by_id(self, version_id: uuid.UUID) -> HsmKeyVersionEntity | None:
        """
        Fetches a single key version by its unique ID.
        """
        query = select(HsmKeyVersionEntity).where(HsmKeyVersionEntity.id == version_id)
        return self.db_session.execute(query).scalars().first()

    def mark_removed(
        self,
        version_id: uuid.UUID,
    ) -> HsmKeyVersionEntity | None:
        """
        Flags an existing key version as removed, leaving its dates untouched.
        Returns `None` when no version exists for that ID.
        """
        now = now_utc()
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
