import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import gfmodules.logging as gflog
from fastapi import HTTPException

from app.db.db import Database
from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.repositories.hsm_key_version_repository import HsmKeyVersionRepository
from app.db.repositories.organization_repository import OrganizationRepository
from app.logging.events import SLEUTELTYPE_OPRF_SECRET, Log
from app.models.oin import Oin
from app.utils.datetime import now_utc

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
        at = at or now_utc()
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            versions = repo.get_active_versions(at, organization_id=organization_id)
            return versions

    def get_active_version_numbers_by_organization_oin(
        self,
        organization_external_id: Oin,
    ) -> list[int]:
        """
        Returns active version numbers for the organization at the current moment.
        """

        def _is_active(version: HsmKeyVersionEntity, now: datetime) -> bool:
            if version.removed_at is not None:
                return False
            if version.from_dt > now:
                return False
            return version.until_dt is None or version.until_dt > now

        now = now_utc()
        with self.__db.get_db_session() as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(organization_external_id)
            if org is None:
                raise HTTPException(
                    status_code=405, detail="Organization does not exist"
                )
            versions = [v.version for v in org.hsm_key_versions if _is_active(v, now)]
            return versions

    def get_expired_versions(
        self, at: datetime | None = None
    ) -> list[HsmKeyVersionEntity]:
        """
        Returns all key versions that have expired (until_dt in the past) but are
        not yet removed, at the given moment (defaults to the current date/time).
        """
        at = at or now_utc()
        with self.__db.get_db_session() as session:
            repo = session.get_repository(HsmKeyVersionRepository)
            versions = repo.get_expired_versions(at)
            return versions

    def increase_version_for_org(
        self,
        organization_external_id: Oin,
        from_dt: datetime | None = None,
        until_dt: datetime | None = None,
    ) -> HsmKeyVersionEntity:
        """
        Increases the key version for the organization identified by the
        organization id. The version number is automatically derived from the
        highest existing version for that organization. When no start moment is
        given, the version becomes active immediately.
        """
        from_dt = from_dt or now_utc()
        with self.__db.get_db_session(commit=True) as session:
            org = session.get_repository(OrganizationRepository).get_one_by_external_id(
                organization_external_id
            )
            if not org:
                raise HTTPException(status_code=401, detail="unauthorized")
            # Make sure we have at least one hsm_key_version
            if not org.hsm_key_versions:
                logger.error(
                    "organization %s has no hsm key version to rotate from",
                    organization_external_id.value,
                )
                raise HTTPException(
                    status_code=409, detail="Organization has no key version"
                )
            # The relationship is ordered by version, so the last entry holds
            # the highest version number.
            current_version = org.hsm_key_versions[-1].version
            hsm_key_version = HsmKeyVersionEntity(
                version=current_version + 1,
                from_dt=from_dt,
                until_dt=until_dt,
            )
            org.hsm_key_versions.append(hsm_key_version)
            session.flush()
            gflog.emit(
                logger,
                Log.KEY_ROTATION_STARTED,
                "HSM key version rotation started",
                fields={
                    "sleuteltype": SLEUTELTYPE_OPRF_SECRET,
                    "organisatie_oin": organization_external_id.value,
                    "oude_versie": current_version,
                    "nieuwe_versie": hsm_key_version.version,
                },
            )
            return hsm_key_version

    def update_version_by_organization_id(
        self,
        version_id: uuid.UUID,
        organization_external_id: Oin,
        until_dt: datetime | None = None,
    ) -> dict[str, Any]:
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
            versions = [hkv for hkv in org.hsm_key_versions if hkv.id == version_id]
            if len(versions) != 1:
                raise HTTPException(status_code=404, detail="KeyVersion not found")
            version = versions[0]
            if version.removed_at is not None:
                raise HTTPException(403, "forbidden")
            version.until_dt = until_dt
            if until_dt is not None:
                gflog.emit(
                    logger,
                    Log.KEY_GRACE_STARTED,
                    "HSM key version grace period started",
                    fields={
                        "sleuteltype": SLEUTELTYPE_OPRF_SECRET,
                        "organisatie_oin": organization_external_id.value,
                        "oude_versie": version.version,
                        "grace_start": datetime.now(timezone.utc).isoformat(),
                        "grace_eind": until_dt.isoformat(),
                    },
                )
            return version.to_dict()

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
