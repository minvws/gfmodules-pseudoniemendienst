from typing import List, Optional, Sequence

from jwcrypto import jwk
from pydantic import BaseModel, Field, field_validator

from app.db.db import Database
from app.db.entities.key_entry import KeyEntry
from app.db.repositories.key_entry_repository import KeyEntryRepository

def _normalize_scope(items: List[str]) -> List[str]:
    cleaned = [s.strip().lower() for s in items if s and s.strip()]
    return sorted(set(cleaned))

class KeyRequest(BaseModel):
    organization: str = Field(..., min_length=2)
    scope: List[str] = Field(...)
    pub_key: str = Field(..., min_length=32)

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
            entry = session.get_repository(KeyEntryRepository).get(organization, scope)

        if entry is None:
            return None

        return jwk.JWK.from_pem(entry.key.encode('ascii'))

    def create(self, organization: str, scope: list[str], pub_key: str) -> KeyEntry:
        scope = _normalize_scope(scope)
        pub_key = pub_key.strip()

        with self.db.get_db_session() as session:
            entry = session.get_repository(KeyEntryRepository).create(organization, scope, pub_key)
            session.commit()
            return entry

    def update(self, entry_id: str, scope: list[str], pub_key: str) -> Optional[KeyEntry]:
        scope = _normalize_scope(scope)
        pub_key = pub_key.strip()

        with self.db.get_db_session() as session:
            entry = session.get_repository(KeyEntryRepository).update(entry_id, scope, pub_key)
            session.commit()
            return entry

    def get_by_id(self, entry_id: str) -> Optional[KeyEntry]:
        with self.db.get_db_session() as session:
            entry = session.get_repository(KeyEntryRepository).get_by_id(entry_id)
        return entry

    def get_by_org(self, organization: str) -> Sequence[KeyEntry]|None:
        with self.db.get_db_session() as session:
            entries = session.get_repository(KeyEntryRepository).get_by_org(organization)
            return entries

    def delete(self, entry_id: str) -> bool:
        with self.db.get_db_session() as session:
            entry = session.get_repository(KeyEntryRepository).get_by_id(entry_id)
            session.session.delete(entry)
            session.commit()
            return True

