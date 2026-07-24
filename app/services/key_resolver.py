import logging
import uuid
from typing import List, Optional, Sequence

from jwcrypto import jwk
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.db import Database
from app.db.entities.organization_key import OrganizationKey
from app.db.repositories.org_key_repository import OrganizationKeyRepository
from app.db.repositories.org_repository import OrgRepository
from app.models.oin import Oin
from app.rid import RidUsage

logger = logging.getLogger(__name__)


class AlreadyExistsError(Exception):
    pass


def _normalize_scope(items: List[str]) -> List[str]:
    cleaned = [s.strip().lower() for s in items if s and s.strip()]
    return sorted(set(cleaned))


class KeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: List[str] = Field(...)
    pub_key: str = Field(..., min_length=32)
    max_key_usage: Optional[RidUsage] = None

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: List[str]) -> List[str]:
        if not v:
            logger.error("scope must contain at least one item")
            raise ValueError("scope must contain at least one item")
        norm = _normalize_scope(v)
        if not norm:
            logger.error("scope contains only empty/invalid items")
            raise ValueError("scope contains only empty/invalid items")
        return norm

    @field_validator("pub_key")
    @classmethod
    def validate_pub_key(cls, v: str) -> str:
        try:
            key = jwk.JWK.from_pem(v.strip().encode("ascii"))
        except Exception as e:
            logger.exception("invalid PEM encoded public key")
            raise ValueError(f"must be a valid PEM encoded public key: {e}")

        if key.has_private:
            logger.error("provided key is a private key, expected a public key")
            raise ValueError("must be a public key, not a private key")

        return v


class KeyResolver:
    def __init__(self, db: Database):
        self.db = db

    def max_rid_usage(self, oin: Oin) -> Optional[RidUsage]:
        with self.db.get_db_session() as session:
            org = session.get_repository(OrgRepository).get_by_oin(oin)
            if org is None:
                return None

        if org.max_rid_usage is None:
            return None
        if org.max_rid_usage == RidUsage.Bsn.value:
            return RidUsage.Bsn
        if org.max_rid_usage == RidUsage.ReversiblePseudonym.value:
            return RidUsage.ReversiblePseudonym
        if org.max_rid_usage == RidUsage.IrreversiblePseudonym.value:
            return RidUsage.IrreversiblePseudonym

        return None

    def resolve_entry(self, org_id: uuid.UUID, scope: str) -> Optional[OrganizationKey]:
        with self.db.get_db_session() as session:
            return session.get_repository(OrganizationKeyRepository).get(org_id, scope)

    def resolve(
        self, org_id: uuid.UUID, scope: str
    ) -> tuple[Optional[jwk.JWK], Optional[str]]:
        entry = self.resolve_entry(org_id, scope)

        if entry is None:
            return None, None

        return jwk.JWK.from_pem(entry.key_data.encode("ascii")), entry.key_id

    def create(
        self, org_id: uuid.UUID, scope: list[str], key_id: Optional[str], key_data: str
    ) -> OrganizationKey:
        scope = _normalize_scope(scope)

        with self.db.get_db_session() as session:
            try:
                repository = session.get_repository(OrganizationKeyRepository)
                if repository.has_overlapping_scope(org_id, scope):
                    raise AlreadyExistsError(
                        f"key for org/scope already exists: scope {scope}"
                    )
                entry = repository.create(org_id, scope, key_data, key_id)
            except AlreadyExistsError:
                raise
            except Exception as e:
                logger.exception(
                    "failed to create key entry for org %s and scope %r",
                    org_id,
                    scope,
                )
                raise AlreadyExistsError(f"key for org/scope already exists: {e}")
            session.commit()
            return entry

    def update(
        self,
        key_id: uuid.UUID,
        organization_id: uuid.UUID,
        scope: list[str],
        key_data: str,
    ) -> Optional[OrganizationKey]:
        scope = _normalize_scope(scope)

        with self.db.get_db_session() as session:
            repository = session.get_repository(OrganizationKeyRepository)

            existing = repository.has_overlapping_scope(organization_id, scope, key_id)
            if existing:
                raise AlreadyExistsError(
                    f"key for org/scope already exists: scope {scope}"
                )

            entry = repository.update(
                key_id,
                organization_id,
                scope,
                key_data,
            )
            if entry is None:
                current = repository.get_by_id(key_id)
                if current is not None:
                    logger.warning(
                        "caller org %s attempted to update key %s owned by org %s",
                        organization_id,
                        key_id,
                        current.organization_id,
                    )

                return None
            session.commit()
            return entry

    def get_by_id(self, key_id: uuid.UUID) -> Optional[OrganizationKey]:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).get_by_id(key_id)
        return entry

    def get_by_org(self, org_id: uuid.UUID) -> Sequence[OrganizationKey] | None:
        with self.db.get_db_session() as session:
            entries = session.get_repository(OrganizationKeyRepository).get_by_org(
                org_id
            )
            return entries

    def delete(self, key_id: uuid.UUID, organization_id: uuid.UUID) -> bool:
        with self.db.get_db_session() as session:
            repository = session.get_repository(OrganizationKeyRepository)
            deleted = repository.delete(key_id, organization_id)
            if not deleted:
                entry = repository.get_by_id(key_id)
                if entry is not None:
                    logger.warning(
                        "caller org %s attempted to delete key %s owned by org %s",
                        organization_id,
                        key_id,
                        entry.organization_id,
                    )

                return False

            session.commit()
            return True
