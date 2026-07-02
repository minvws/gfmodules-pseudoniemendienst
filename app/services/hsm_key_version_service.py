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

logger = logging.getLogger(__name__)


class HsmKeyVersionNotFoundError(ValueError):
    """Raised when the key version does not exist, is already removed, or mismatches."""

    def __init__(self, version_id: uuid.UUID, organization_id: uuid.UUID):
        super().__init__(
            f"key version {version_id} for organization {organization_id} not found"
        )
        self.version_id = version_id
        self.organization = organization_id


class HsmKeyVersionService:
    """Manages HSM key versions in the local database."""

    def __init__(self, db: Database) -> None:
        self.__db = db

    def get_active_versions_by_organization_id(
        self,
        organization_id: uuid.UUID,
        at: datetime | None = None,
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that are active at the given moment (defaults to
        the current date/time), restricted to a single organization id.
        """
        at = at or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            return repo.get_active_versions(at, organization_id)

    def get_versions_by_organization_id(
        self,
        organization_id: uuid.UUID,
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions for the given organization id, regardless of
        date or removed state (for administrative listing).
        """
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            return repo.get_by_organization_id(organization_id)

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

    def create_version_by_organization_id(
        self,
        organization_id: uuid.UUID,
        from_dt: datetime | None = None,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersion:
        """
        Creates a new key version for the organization identified by the
        organization id. The version number is automatically derived from the
        highest existing version for that organization. When no start moment is
        given, the version becomes active immediately.
        """
        from_dt = from_dt or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                entry = repo.create(
                    organization_id=organization_id,
                    from_dt=from_dt,
                    until_dt=until_dt,
                )
                session.commit()
                return entry
            except Exception:
                session.rollback()
                logger.exception(
                    "failed to create hsm key version for organization_id %s",
                    organization_id,
                )
                raise

    def update_version_by_organization_id(
        self,
        version_id: uuid.UUID,
        organization_id: uuid.UUID,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersion:
        """
        Updates the end date of an existing active key version for the
        organization identified by its id. The removed flag is not
        user-controllable here.
        Raises when the version does not exist, is already removed, or belongs to a
        different organization.
        """
        with self.__db.get_db_session() as session:
            try:
                repo = session.get_repository(HsmKeyVersionRepository)
                entry = repo.update(version_id, organization_id, until_dt)
                session.commit()
                return entry
            except HsmKeyVersionRepositoryNotFoundError as exc:
                logger.warning(
                    "update failed: key version %s for organization_id %s not found",
                    version_id,
                    organization_id,
                )
                session.rollback()
                raise HsmKeyVersionNotFoundError(
                    exc.version_id, organization_id
                ) from exc
            except Exception:
                session.rollback()
                logger.exception(
                    "failed to update hsm key version %s for organization_id %s",
                    version_id,
                    organization_id,
                )
                raise

    def mark_removed_by_organization_id(
        self,
        version_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> HsmKeyVersion:
        """Flags a key version as removed by organization id."""
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                entry = repo.mark_removed(version_id, organization_id)
                session.commit()
                return entry
            except HsmKeyVersionRepositoryNotFoundError as exc:
                session.rollback()
                logger.warning(
                    "mark removed failed for key version %s for organization_id %s",
                    version_id,
                    organization_id,
                )
                raise HsmKeyVersionNotFoundError(
                    exc.version_id,
                    organization_id,
                ) from exc
            except Exception:
                session.rollback()
                logger.exception(
                    "failed to mark hsm key version %s for organization_id %s as removed",
                    version_id,
                    organization_id,
                )
                raise
