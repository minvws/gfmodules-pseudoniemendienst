import logging
import uuid
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import and_, func, insert, or_, select, update

from app.db.decorator import repository
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.repositories.repository_base import RepositoryBase
from app.models.oin import Oin

logger = logging.getLogger(__name__)


class HsmKeyVersionNotFoundError(ValueError):
    """Raised when a version or removal target cannot be matched for the OIN."""

    def __init__(self, version_id: uuid.UUID, oin: Oin):
        super().__init__(f"hsm key version {version_id} for OIN {oin} not found")
        self.version_id = version_id
        self.oin = oin


@repository(HsmKeyVersion)
class HsmKeyVersionRepository(RepositoryBase):
    def get_active_versions(self, at: datetime, oin: Oin) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that are active at the given moment, i.e. not
        removed, already started (from_dt <= at) and not yet ended (until_dt is
        unset or still in the future), restricted to the organization with that
        OIN.
        """
        query = select(HsmKeyVersion).where(
            HsmKeyVersion.oin == oin,
            HsmKeyVersion.removed.is_(False),
            HsmKeyVersion.from_dt <= at,
            or_(HsmKeyVersion.until_dt.is_(None), HsmKeyVersion.until_dt >= at),
        )
        return self.db_session.execute(query).scalars().all()

    def get_by_oin(self, oin: Oin) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions belonging to the organization with the given OIN,
        regardless of date or removed state, ordered by version number.
        """
        query = (
            select(HsmKeyVersion)
            .where(HsmKeyVersion.oin == oin)
            .order_by(HsmKeyVersion.version)
        )
        return self.db_session.execute(query).scalars().all()

    def get_expired_versions(self, at: datetime) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that have passed their end date (until_dt is set
        and in the past) but have not been removed yet. The organization is eagerly
        loaded so its OIN stays available after the session is closed.
        """
        query = select(HsmKeyVersion).where(
            HsmKeyVersion.removed.is_(False),
            HsmKeyVersion.until_dt.is_not(None),
            HsmKeyVersion.until_dt < at,
        )
        return self.db_session.execute(query).scalars().all()

    def create(
        self,
        oin: Oin,
        from_dt: datetime,
        until_dt: Optional[datetime] = None,
    ) -> HsmKeyVersion:
        """
        Inserts a new key version entry for the given organization.
        """
        next_version = (
            select(func.coalesce(func.max(HsmKeyVersion.version), 0) + 1)
            .where(HsmKeyVersion.oin == oin)
            .scalar_subquery()
        )

        statement = (
            insert(HsmKeyVersion)
            .values(
                oin=oin,
                version=next_version,
                from_dt=from_dt,
                until_dt=until_dt,
            )
            .returning(HsmKeyVersion)
        )

        entry: HsmKeyVersion = self.db_session.execute(statement).scalars().one()

        logger.info("created hsm key version %s for OIN %s", entry.version, oin)
        return entry

    def update(
        self,
        version_id: uuid.UUID,
        oin: Oin,
        until_dt: Optional[datetime],
    ) -> HsmKeyVersion:
        """
        Updates the end date of an existing active key version for the organization
        identified by the provided OIN. Raises HsmKeyVersionNotFoundError when no
        active version exists for that ID in that organization.
        """
        statement = (
            update(HsmKeyVersion)
            .where(
                and_(
                    HsmKeyVersion.id == version_id,
                    HsmKeyVersion.removed.is_(False),
                    HsmKeyVersion.oin == oin,
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
                "hsm key version %s for OIN %s does not exist or is already removed",
                version_id,
                oin,
            )
            raise HsmKeyVersionNotFoundError(version_id, oin)

        logger.info("updated hsm key version %s for OIN %s", version_id, oin)
        return entry

    def mark_removed(self, version_id: uuid.UUID, oin: Oin) -> HsmKeyVersion:
        """
        Flags an existing key version as removed, leaving its dates untouched.
        Raises HsmKeyVersionNotFoundError when no version exists for that ID/OIN.
        """
        statement = (
            update(HsmKeyVersion)
            .where(
                and_(
                    HsmKeyVersion.id == version_id,
                    HsmKeyVersion.removed.is_(False),
                    HsmKeyVersion.oin == oin,
                )
            )
            .values(removed=True)
            .returning(HsmKeyVersion)
        )

        entry: Optional[HsmKeyVersion] = (
            self.db_session.execute(statement).scalars().one_or_none()
        )
        if entry is None:
            logger.warning(
                "hsm key version with id %s for OIN %s does not exist or is already removed",
                version_id,
                oin,
            )
            raise HsmKeyVersionNotFoundError(version_id, oin)

        return entry
