import logging
import uuid
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import and_, func, insert, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload

from app.db.decorator import repository
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.repositories.repository_base import RepositoryBase

logger = logging.getLogger(__name__)


class HsmKeyVersionNotFoundError(ValueError):
    """Raised when a version or removal target cannot be matched for organization."""

    def __init__(self, version_id: uuid.UUID, organization_id: uuid.UUID):
        super().__init__(
            f"hsm key version {version_id} for organization_id {organization_id} not found"
        )
        self.version_id = version_id
        self.organization_id = organization_id


class HsmKeyVersionCreateConflictError(ValueError):
    """Raised when creating a key version conflicts with an existing row."""

    def __init__(self, organization_id: uuid.UUID):
        super().__init__(
            f"hsm key version creation for organization_id {organization_id} conflicts with"
            " existing version"
        )
        self.organization_id = organization_id


@repository(HsmKeyVersion)
class HsmKeyVersionRepository(RepositoryBase):
    def get_active_versions(
        self, at: datetime, organization_id: uuid.UUID
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that are active at the given moment, i.e. not
        removed, already started (from_dt <= at) and not yet ended (until_dt is
        unset or still in the future), restricted to organization_id.
        """
        query = (
            select(HsmKeyVersion)
            .where(
                HsmKeyVersion.organization_id == organization_id,
                HsmKeyVersion.removed.is_(False),
                HsmKeyVersion.from_dt <= at,
                or_(HsmKeyVersion.until_dt.is_(None), HsmKeyVersion.until_dt >= at),
            )
            .order_by(HsmKeyVersion.version)
        )
        return self.db_session.execute(query).scalars().all()

    def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions belonging to the organization with the given id,
        regardless of date or removed state, ordered by version number.
        """
        query = (
            select(HsmKeyVersion)
            .where(HsmKeyVersion.organization_id == organization_id)
            .order_by(HsmKeyVersion.version)
        )
        return self.db_session.execute(query).scalars().all()

    def get_expired_versions(self, at: datetime) -> Sequence[HsmKeyVersion]:
        """
        Returns all key versions that have passed their end date (until_dt is set
        and in the past) but have not been removed yet. The organization is eagerly
        loaded so its OIN stays available after the session is closed.
        """
        query = (
            select(HsmKeyVersion)
            .where(
                HsmKeyVersion.removed.is_(False),
                HsmKeyVersion.until_dt.is_not(None),
                HsmKeyVersion.until_dt < at,
            )
            .options(joinedload(HsmKeyVersion.organization))
        )
        return self.db_session.execute(query).unique().scalars().all()

    def create(
        self,
        organization_id: uuid.UUID,
        from_dt: datetime,
        until_dt: Optional[datetime] = None,
    ) -> HsmKeyVersion:
        """
        Inserts a new key version entry for the given organization id.
        """
        next_version = (
            select(func.coalesce(func.max(HsmKeyVersion.version), 0) + 1)
            .where(HsmKeyVersion.organization_id == organization_id)
            .scalar_subquery()
        )

        statement = (
            insert(HsmKeyVersion)
            .values(
                organization_id=organization_id,
                version=next_version,
                from_dt=from_dt,
                until_dt=until_dt,
            )
            .returning(HsmKeyVersion)
        )

        try:
            entry: HsmKeyVersion = self.db_session.execute(statement).scalars().one()
        except IntegrityError as exc:
            raise HsmKeyVersionCreateConflictError(organization_id) from exc

        logger.info(
            "created hsm key version %s for organization_id %s",
            entry.version,
            organization_id,
        )
        return entry

    def update(
        self,
        version_id: uuid.UUID,
        organization_id: uuid.UUID,
        until_dt: Optional[datetime],
    ) -> HsmKeyVersion:
        """
        Updates the end date of an existing active key version for the organization
        identified by organization_id. Raises HsmKeyVersionNotFoundError when no
        active version exists for that ID in that organization.
        """
        statement = (
            update(HsmKeyVersion)
            .where(
                and_(
                    HsmKeyVersion.id == version_id,
                    HsmKeyVersion.removed.is_(False),
                    HsmKeyVersion.organization_id == organization_id,
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
                "hsm key version %s for organization_id %s does not exist",
                version_id,
                organization_id,
            )
            raise HsmKeyVersionNotFoundError(version_id, organization_id)

        logger.info(
            "updated hsm key version %s for organization_id %s",
            version_id,
            organization_id,
        )
        return entry

    def mark_removed(
        self, version_id: uuid.UUID, organization_id: uuid.UUID
    ) -> HsmKeyVersion:
        """
        Flags an existing key version as removed, leaving its dates untouched.
        Raises HsmKeyVersionNotFoundError when no version exists for that ID/id.
        """
        statement = (
            update(HsmKeyVersion)
            .where(
                and_(
                    HsmKeyVersion.id == version_id,
                    HsmKeyVersion.removed.is_(False),
                    HsmKeyVersion.organization_id == organization_id,
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
                "hsm key version with id %s for organization_id %s does not exist",
                version_id,
                organization_id,
            )
            raise HsmKeyVersionNotFoundError(version_id, organization_id)

        return entry
