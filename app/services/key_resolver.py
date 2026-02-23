import logging
import uuid
from typing import List, Optional, Sequence

from jwcrypto import jwk
from pydantic import BaseModel, Field, field_validator

from app.db.db import Database
from app.db.entities.organization_key import OrganizationKey
from app.db.repositories.org_key_repository import OrganizationKeyRepository
from app.db.repositories.org_repository import OrgRepository
from app.rid import RidUsage

logger = logging.getLogger(__name__)


class AlreadyExistsError(Exception):
    pass

def _normalize_scope(items: List[str]) -> List[str]:
    cleaned = [s.strip().lower() for s in items if s and s.strip()]
    return sorted(set(cleaned))

class KeyRequest(BaseModel):
    organization: str = Field(..., min_length=2)
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
            v = v.strip()
            key = jwk.JWK.from_pem(v.encode('ascii'))
        except Exception as e:
            logger.error("invalid PEM encoded public key: %r", e)
            raise ValueError(f"must be a valid PEM encoded public key: {e}")

        if key.has_private:
            logger.error("provided key is a private key, expected a public key")
            raise ValueError("must be a public key, not a private key")

        return v


class KeyResolver:
    def __init__(self, db: Database):
        self.db = db

    def max_rid_usage(self, ura: str) -> Optional[RidUsage]:
        with self.db.get_db_session() as session:
            org = session.get_repository(OrgRepository).get_by_ura(ura)
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

    def resolve(self, org_id: uuid.UUID, scope: str) -> Optional[jwk.JWK]:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).get(org_id, scope)

        if entry is None:
            return None

        return jwk.JWK.from_pem(entry.key_data.encode('ascii'))

    def create(self, org_id: uuid.UUID, scope: list[str], key_data: str) -> OrganizationKey:
        scope = _normalize_scope(scope)
        key_data = key_data.strip()

        with self.db.get_db_session() as session:
            try:
                entry = session.get_repository(OrganizationKeyRepository).create(org_id, scope, key_data)
            except Exception as e:
                logger.error(
                    "failed to create key entry for org %s and scope %r: %r",
                    org_id,
                    scope,
                    e,
                )
                raise AlreadyExistsError(f"key for org/scope already exists: {e}")
            session.commit()
            return entry

    def update(self, key_id: uuid.UUID, scope: list[str], key_data: str) -> Optional[OrganizationKey]:
        scope = _normalize_scope(scope)
        key_data = key_data.strip()

        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).update(key_id, scope, key_data)
            session.commit()
            return entry

    def get_by_id(self, key_id: uuid.UUID) -> Optional[OrganizationKey]:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).get_by_id(key_id)
        return entry

    def get_by_org(self, org_id: uuid.UUID) -> Sequence[OrganizationKey]|None:
        with self.db.get_db_session() as session:
            entries = session.get_repository(OrganizationKeyRepository).get_by_org(org_id)
            return entries

    def delete(self, key_id: uuid.UUID) -> bool:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).get_by_id(key_id)
            session.session.delete(entry)
            session.commit()
            return True

    def delete_by_org(self, org_id: uuid.UUID) -> int:
        with self.db.get_db_session() as session:
            count = session.get_repository(OrganizationKeyRepository).delete_by_org(org_id)
            session.commit()
            return count
