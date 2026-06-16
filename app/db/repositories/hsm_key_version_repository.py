import logging
from datetime import datetime
from typing import Sequence

from sqlalchemy import or_, select

from app.db.decorator import repository
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.repositories.repository_base import RepositoryBase

logger = logging.getLogger(__name__)


@repository(HsmKeyVersion)
class HsmKeyVersionRepository(RepositoryBase):
    def get_active_versions(self, at: datetime) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that are active at the given moment, i.e. not
        removed, already started (from_dt <= at) and not yet ended (until_dt is
        unset or still in the future).
        """
        query = select(HsmKeyVersion).where(
            HsmKeyVersion.removed.is_(False),
            HsmKeyVersion.from_dt <= at,
            or_(HsmKeyVersion.until_dt.is_(None), HsmKeyVersion.until_dt >= at),
        )
        return self.db_session.session.execute(query).scalars().all()
