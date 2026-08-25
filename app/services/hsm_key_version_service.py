import logging
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException

from app.db.db import Database
from app.db.models import organization
from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.repositories.hsm_key_version_repository import HsmKeyVersionRepository
from app.db.repositories.organization_repository import OrganizationRepository
from app.models.oin import Oin

logger = logging.getLogger(__name__)


class HsmKeyVersionNotFoundError(ValueError):
    """Raised when the key version does not exist, is already removed, or mismatches."""

    def __init__(self, version_id: uuid.UUID, organization_id: uuid.UUID):
        super().__init__(
            f"key version {version_id} for organization {organization_id} not found"
        )
        self.version_id = version_id
        self.organization_id = organization_id


class HsmKeyVersionCreateConflictError(ValueError):
    """Raised when creating a key version conflicts with an existing row."""

    def __init__(self, organization_id: uuid.UUID):
        super().__init__(
            f"hsm key version creation for organization_id {organization_id} conflicts "
            "with existing version"
        )
        self.organization_id = organization_id


class HsmKeyVersionService:
    """Manages HSM key versions in the local database."""

    def __init__(self, db: Database) -> None:
        self.__db = db

    def get_version(self, version_id: uuid.UUID) -> HsmKeyVersionEntity | None:
        """
        Returns a single key version by its ID, or None when it does not exist.
        """
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            return repo.get_by_id(version_id)

    def get_versions_by_organization_id(
        self,
        organization_external_id: Oin,
    ) -> list[HsmKeyVersionEntity]:
        """
        Returns all key versions for the given organization id, regardless of
        date or removed state (for administrative listing).
        """
        with self.__db.get_db_session() as session:
            organization = session.get_repository(
                OrganizationRepository
            ).get_one_by_external_id(organization_external_id)
            if not organization:
                raise HTTPException(status_code=404, detail="Organization not found")
            return organization.hsm_key_versions

    def get_active_versions_by_organization_id(
        self,
        organization_id: uuid.UUID,
        at: datetime | None = None,
    ) -> list[HsmKeyVersionEntity]:
        """
        Returns all key versions that are active at the given moment (defaults to
        the current date/time), restricted to a single organization id.
        """
        at = at or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            versions = repo.get_active_versions(at, organization_id=organization_id)
            return versions

    def get_active_versions_by_organization_oin(
        self,
        oin: Oin,
        at: datetime | None = None,
    ) -> list[HsmKeyVersionEntity]:
        """
        Returns all active key versions for the organization with the provided OIN.
        """
        at = at or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            versions = repo.get_active_versions_by_organization_oin(
                at, organization_oin=oin
            )
            return versions

    def get_active_or_create_version_numbers_by_organization_id(
        self,
        organization_id: uuid.UUID,
    ) -> list[int]:
        """
        Returns active version numbers for the organization at the current moment.

        If no active version exists yet, creates one and returns its version
        number.
        """
        at = datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                versions = repo.get_active_or_create_version_numbers_by_organization_id(
                    organization_id=organization_id,
                    at=at,
                )
                session.commit()
                if not versions:
                    raise RuntimeError(
                        f"failed to obtain active key version numbers for organization_id {organization_id}"
                    )
                return versions
            except Exception:
                session.rollback()
                logger.exception(
                    "failed active-or-create key version numbers for organization_id %s",
                    organization_id,
                )
                raise

    def get_expired_versions(
        self, at: datetime | None = None
    ) -> list[HsmKeyVersionEntity]:
        """
        Returns all key versions that have expired (until_dt in the past) but are
        not yet removed, at the given moment (defaults to the current date/time).
        """
        at = at or datetime.now(timezone.utc)
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            versions = repo.get_expired_versions(at)
            return versions

    def create_version(
        self,
        organization_id: uuid.UUID,
        from_dt: datetime | None = None,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersionEntity:
        """
        Creates a new key version for the organization identified by the given
        OIN. The version number is automatically derived from the highest
        existing version for that organization. When no start moment is given,
        the version becomes active immediately.

        Raises a ValueError when no organization exists for the given OIN.
        TODO GB: Update doc
        """
        return self.create_version_by_organization_external_id(
            organization_id,
            from_dt=from_dt,
            until_dt=until_dt,
        )

    def create_version_by_organization_external_id(
        self,
        organization_external_id: Oin,
        from_dt: datetime | None = None,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersionEntity:
        """
        Creates a new key version for the organization identified by the
        organization id. The version number is automatically derived from the
        highest existing version for that organization. When no start moment is
        given, the version becomes active immediately.
        """
        from_dt = from_dt or datetime.now(timezone.utc)
        with self.__db.get_db_session(commit=True) as session:
            org = session.get_repository(OrganizationRepository).get_one_by_external_id(
                organization_external_id
            )
            if not org:
                raise HTTPException(status_code=404, detail="Organization not found")
            hsm_key_version = HsmKeyVersionEntity(
                version=org.hsm_key_versions[-1].version + 1,
                from_dt=from_dt,
                until_dt=until_dt,
            )
            org.hsm_key_versions.append(hsm_key_version)
            session.flush()
            return hsm_key_version

    def update_version_by_organization_id(
        self,
        version_id: uuid.UUID,
        organization_external_id: Oin,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersionEntity:
        """
        Updates the end date of an existing key version for the specified
        organization id. Raises when the version does not exist or belongs to
        another organization.
        """
        with self.__db.get_db_session(commit=True) as session:
            org = session.get_repository(OrganizationRepository).get_one_by_external_id(
                organization_external_id
            )
            if not org:
                raise HTTPException(status_code=404, detail="Organization not found")
            versions = [hkv for hkv in org.hsm_key_versions where hkv.id == version_id]
            if len(versions) != 1:
                raise HTTPException(status_code=404, detail="KeyVersion not found")
            version = versions[0]
            # TODO GB: Validation errors?
            version.until_dt == until_dt

            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                updated = repo.update(version_id, organization_id, until_dt)
                if updated is None:
                    current = repo.get_by_id(version_id)
                    if (
                        current is not None
                        and current.organization_id != organization_id
                    ):
                        logger.warning(
                            "caller org %s attempted to update key version %s owned by org %s",
                            organization_id,
                            version_id,
                            current.organization_id,
                        )
                    raise HsmKeyVersionNotFoundError(version_id, organization_id)

                target_version = updated
                session.commit()
                return target_version
            except HsmKeyVersionNotFoundError:
                session.rollback()
                raise
            except Exception:
                session.rollback()
                logger.exception(
                    "failed to update hsm key version %s for organization_id %s",
                    version_id,
                    organization_id,
                )
                raise

    def mark_removed(self, version_id: uuid.UUID) -> HsmKeyVersionEntity | None:
        """
        Flags a key version as removed (without touching its dates). Returns None
        when no version exists for the given ID.
        """
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            try:
                updated = repo.mark_removed(version_id)
                if updated is None:
                    return None
                session.commit()
                return updated
            except Exception:
                session.rollback()
                logger.exception(
                    "failed to mark hsm key version %s as removed", version_id
                )
                raise
