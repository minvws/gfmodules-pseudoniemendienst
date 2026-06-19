import logging
import uuid
from datetime import datetime, timezone
from typing import Sequence

from app.db.db import Database
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.repositories.hsm_key_version_repository import HsmKeyVersionRepository
from app.db.repositories.org_repository import OrgRepository

logger = logging.getLogger(__name__)


class HsmKeyVersionService:
    """
    Looks up the currently active HSM key versions from the database, replacing
    the former beheer-api lookup.
    """

    def __init__(self, db: Database) -> None:
        self.__db = db

    def get_active_versions(
        self, at: datetime | None = None, ura: str | None = None
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that are active at the given moment (defaults to
        the current date/time), optionally restricted to a single organization's
        URA.
        """
        at = at or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            return repo.get_active_versions(at, ura)

    def get_versions_for_ura(self, ura: str) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions for the given organization URA, regardless of
        date or removed state (for administrative listing).
        """
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            return repo.get_by_ura(ura)

    def get_expired_versions(
        self, at: datetime | None = None
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that have expired (until_dt in the past) but are
        not yet removed, at the given moment (defaults to the current date/time).
        """
        at = at or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            return repo.get_expired_versions(at)

    def create_version(
        self,
        ura: str,
        from_dt: datetime | None = None,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersion:
        """
        Creates a new key version for the organization identified by the given
        URA. The version number is automatically derived from the highest
        existing version for that organization. When no start moment is given,
        the version becomes active immediately.

        Raises a ValueError when no organization exists for the given URA.
        """
        from_dt = from_dt or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            org = session.get_repository(OrgRepository).get_by_ura(ura)
            if org is None:
                raise ValueError(f"organization with ura {ura} not found")

            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                next_version = repo.get_max_version(org.id) + 1
                entry = repo.create(org.id, next_version, from_dt, until_dt)
                # Populate the relationship so to_dict() works after the session
                # is closed (avoids a detached lazy-load of the organization).
                entry.organization = org
                session.commit()
            except Exception:
                session.rollback()
                logger.exception("failed to create hsm key version for ura %s", ura)
                raise

            return entry

    def update_version(
        self,
        version_id: uuid.UUID,
        until_dt: datetime | None = None,
        removed: bool = False,
    ) -> HsmKeyVersion | None:
        """
        Updates the end date and removed flag of an existing key version.
        Returns None when no version exists for the given ID.
        """
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                entry = repo.update(version_id, until_dt, removed)
                if entry is None:
                    return None
                session.commit()
            except Exception:
                session.rollback()
                logger.exception("failed to update hsm key version %s", version_id)
                raise

            return entry

    def mark_removed(self, version_id: uuid.UUID) -> HsmKeyVersion | None:
        """
        Flags a key version as removed (without touching its dates). Returns None
        when no version exists for the given ID.
        """
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                entry = repo.mark_removed(version_id)
                if entry is None:
                    return None
                session.commit()
            except Exception:
                session.rollback()
                logger.exception(
                    "failed to mark hsm key version %s as removed", version_id
                )
                raise

            return entry
