import logging
import uuid
from datetime import datetime, timezone
from typing import Sequence

from app.db.db import Database
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.repositories.hsm_key_version_repository import HsmKeyVersionRepository
from app.db.repositories.hsm_key_version_repository import (
    HsmKeyVersionNotFoundError as HsmKeyVersionRepositoryNotFoundError,
)
from app.models.oin import Oin

logger = logging.getLogger(__name__)


class HsmKeyVersionNotFoundError(ValueError):
    """Raised when the key version does not exist, is already removed, or mismatches."""

    def __init__(self, version_id: uuid.UUID, oin: Oin):
        super().__init__(f"key version {version_id} for OIN {oin} not found")
        self.version_id = version_id
        self.oin = oin


class HsmKeyVersionService:
    """Manages HSM key versions in the local database."""

    def __init__(self, db: Database) -> None:
        self.__db = db

    def get_active_versions(
        self,
        oin: Oin,
        at: datetime | None = None,
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that are active at the given moment (defaults to
        the current date/time), restricted to a single organization's OIN.
        """
        at = at or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            return repo.get_active_versions(at, oin)

    def get_versions_for_oin(self, oin: Oin) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions for the given organization OIN, regardless of
        date or removed state (for administrative listing).
        """
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            return repo.get_by_oin(oin)

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
        oin: Oin,
        from_dt: datetime | None = None,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersion:
        """
        Creates a new key version for the organization identified by the given
        OIN. The version number is automatically derived from the highest
        existing version for that organization. When no start moment is given,
        the version becomes active immediately.
        """
        from_dt = from_dt or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                entry = repo.create(oin=oin, from_dt=from_dt, until_dt=until_dt)
                session.commit()
            except Exception:
                session.rollback()
                logger.exception("failed to create hsm key version for oin %s", oin)
                raise

            return entry

    def update_version(
        self,
        version_id: uuid.UUID,
        oin: Oin,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersion:
        """
        Updates the end date of an existing active key version for the authenticated
        organization (OIN). The removed flag is not user-controllable here.
        Raises when the version does not exist, is already removed, or belongs to a
        different organization.
        """
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                entry = repo.update(version_id, oin, until_dt)
                session.commit()
                return entry
            except HsmKeyVersionRepositoryNotFoundError as exc:
                logger.warning(
                    "update failed: key version %s for OIN %s not found",
                    version_id,
                    oin,
                )
                session.rollback()
                raise HsmKeyVersionNotFoundError(exc.version_id, exc.oin) from exc
            except Exception:
                session.rollback()
                logger.exception(
                    "failed to update hsm key version %s for OIN %s", version_id, oin
                )
                raise

    def mark_removed(self, version_id: uuid.UUID, oin: Oin) -> HsmKeyVersion:
        """
        Flags a key version as removed (without touching its dates).
        """
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                entry = repo.mark_removed(version_id, oin)
                session.commit()
                return entry
            except HsmKeyVersionRepositoryNotFoundError as exc:
                logger.warning(
                    "mark removed failed for key version %s for OIN %s",
                    version_id,
                    oin,
                )
                session.rollback()
                raise HsmKeyVersionNotFoundError(exc.version_id, exc.oin) from exc
            except Exception:
                session.rollback()
                logger.exception(
                    "failed to mark hsm key version %s for OIN %s as removed",
                    version_id,
                    oin,
                )
                raise
