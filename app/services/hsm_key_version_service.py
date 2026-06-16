import logging
from datetime import datetime, timezone
from typing import Sequence

from app.db.db import Database
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.repositories.hsm_key_version_repository import HsmKeyVersionRepository

logger = logging.getLogger(__name__)


class HsmKeyVersionService:
    """
    Looks up the currently active HSM key versions from the database, replacing
    the former beheer-api lookup.
    """

    def __init__(self, db: Database) -> None:
        self.__db = db

    def get_active_versions(
        self, at: datetime | None = None
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that are active at the given moment (defaults to
        the current date/time).
        """
        at = at or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            return repo.get_active_versions(at)
