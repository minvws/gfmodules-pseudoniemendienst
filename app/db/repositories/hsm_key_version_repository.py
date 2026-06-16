import logging
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import or_, select
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
