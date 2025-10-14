from typing import List, Optional, Sequence

from jwcrypto import jwk
from pydantic import BaseModel, Field, field_validator

from app.db.db import Database
from app.db.entities.organization_key import OrganizationKey
from app.db.repositories.org_key_repository import OrganizationKeyRepository
from app.rid import RidUsage


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
            raise ValueError("scope must contain at least one item")
        norm = _normalize_scope(v)
        if not norm:
            raise ValueError("scope contains only empty/invalid items")
        return norm

    @field_validator("pub_key")
    @classmethod
    def validate_pub_key(cls, v: str) -> str:
        try:
            v = v.strip()
            key = jwk.JWK.from_pem(v.encode('ascii'))
        except Exception as e:
            raise ValueError(f"must be a valid PEM encoded public key: {e}")

        if key.has_private:
            raise ValueError("must be a public key, not a private key")

        return v


class KeyResolver:
    def __init__(self, db: Database):
        self.db = db

    def resolve(self, organization: str, scope: str) -> Optional[jwk.JWK]:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).get(organization, scope)

        if entry is None:
            return None

        return jwk.JWK.from_pem(entry.key.encode('ascii'))

    def max_rid_usage(self, organization: str, scope: str) -> Optional[RidUsage]:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).get(organization, scope)

        if entry is None:
            return None

        if entry.max_rid_usage is None:
            return None
        if entry.max_rid_usage == RidUsage.Bsn.value:
            return RidUsage.Bsn
        if entry.max_rid_usage == RidUsage.ReversiblePseudonym.value:
            return RidUsage.ReversiblePseudonym
        if entry.max_rid_usage == RidUsage.IrreversiblePseudonym.value:
            return RidUsage.IrreversiblePseudonym

        return None

    def create(self, org_id: str, scope: list[str], key_data: str) -> OrganizationKey:
        scope = _normalize_scope(scope)
        key_data = key_data.strip()

        with self.db.get_db_session() as session:
            try:
                entry = session.get_repository(OrganizationKeyRepository).create(org_id, scope, key_data)
            except Exception as e:
                raise AlreadyExistsError(f"key for org/scope already exists: {e}")
            session.commit()
            return entry

    def update(self, entry_id: str, scope: list[str], key_data: str) -> Optional[OrganizationKey]:
        scope = _normalize_scope(scope)
        key_data = key_data.strip()

        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).update(entry_id, scope, key_data)
            session.commit()
            return entry

    def get_by_id(self, entry_id: str) -> Optional[OrganizationKey]:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).get_by_id(entry_id)
        return entry

    def get_by_org(self, org_id: str) -> Sequence[OrganizationKey]|None:
        with self.db.get_db_session() as session:
            entries = session.get_repository(OrganizationKeyRepository).get_by_org(org_id)
            return entries

    def delete(self, entry_id: str) -> bool:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationKeyRepository).get_by_id(entry_id)
            session.session.delete(entry)
            session.commit()
            return True

    def delete_by_org(self, ura: str) -> int:
        with self.db.get_db_session() as session:
            count = session.get_repository(OrganizationKeyRepository).delete_by_org(ura)
            session.commit()
            return count
