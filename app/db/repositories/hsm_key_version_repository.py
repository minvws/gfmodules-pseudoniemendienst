import logging
import uuid
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.orm import joinedload

from app.db.decorator import repository
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.entities.organization import Organization
from app.db.repositories.repository_base import RepositoryBase

logger = logging.getLogger(__name__)


@repository(HsmKeyVersion)
class HsmKeyVersionRepository(RepositoryBase):
    def get_active_versions(
        self, at: datetime, ura: Optional[str] = None
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that are active at the given moment, i.e. not
        removed, already started (from_dt <= at) and not yet ended (until_dt is
        unset or still in the future). When a URA is supplied, only the versions
        belonging to that organization are returned.
        """
        query = (
            select(HsmKeyVersion)
            .options(joinedload(HsmKeyVersion.organization))
            .where(
                HsmKeyVersion.removed.is_(False),
                HsmKeyVersion.from_dt <= at,
                or_(HsmKeyVersion.until_dt.is_(None), HsmKeyVersion.until_dt >= at),
            )
        )
        if ura is not None:
            query = query.join(Organization).where(Organization.ura == ura)
        return self.db_session.session.execute(query).scalars().all()

    def get_max_version(self, organization_id: uuid.UUID) -> int:
        """
        Returns the highest version number currently stored for the given
        organization, or 0 when no versions exist yet.
        """
        query = select(func.max(HsmKeyVersion.version)).where(
            HsmKeyVersion.organization_id == organization_id
        )
        return self.db_session.execute(query).scalar() or 0

    def create(
        self,
        organization_id: uuid.UUID,
        version: int,
        from_dt: datetime,
        until_dt: Optional[datetime] = None,
    ) -> HsmKeyVersion:
        """
        Inserts a new key version entry for the given organization.
        """
        entry = HsmKeyVersion(
            organization_id=organization_id,
            version=version,
            from_dt=from_dt,
            until_dt=until_dt,
        )
        self.db_session.session.add(entry)
        self.db_session.session.flush()

        logger.info(
            "created hsm key version %s for organization %s", version, organization_id
        )
        return entry

    def get_by_id(self, version_id: uuid.UUID) -> Optional[HsmKeyVersion]:
        """
        Fetches a single key version by its unique ID, eagerly loading the
        organization so it remains available after the session is closed.
        """
        query = (
            select(HsmKeyVersion)
            .options(joinedload(HsmKeyVersion.organization))
            .where(HsmKeyVersion.id == version_id)
        )
        return self.db_session.session.execute(query).scalars().first()

    def update(
        self,
        version_id: uuid.UUID,
        until_dt: Optional[datetime],
        removed: bool,
    ) -> Optional[HsmKeyVersion]:
        """
        Updates the end date and removed flag of an existing key version.
        Returns None when no version exists for the given ID.
        """
        entry = self.get_by_id(version_id)
        if entry is None:
            logger.warning("hsm key version with id %s does not exist", version_id)
            return None

        entry.until_dt = until_dt  # type: ignore
        entry.removed = removed  # type: ignore
        self.db_session.session.add(entry)
        self.db_session.session.flush()

        logger.info("updated hsm key version %s", version_id)
        return entry
