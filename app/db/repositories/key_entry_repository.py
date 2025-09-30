import logging
from typing import Sequence, Optional

from sqlalchemy.dialects.postgresql.json import JSONB

from app.db.decorator import repository
from app.db.entities.key_entry import KeyEntry
from app.db.repositories.repository_base import RepositoryBase
from sqlalchemy import select, or_, literal

logger = logging.getLogger(__name__)


@repository(KeyEntry)
class KeyEntryRepository(RepositoryBase):

    def get(self, organization: str, scope: str) -> Optional[KeyEntry]:
        """
        Fetches the key entry by organization and scope.
        If a key entry has scope *, it will match everything
        """
        query = (select(KeyEntry)
            .where(KeyEntry.organization == organization)
            .where(or_(
                KeyEntry.scope.contains(literal([scope], JSONB)),
                KeyEntry.scope.contains(literal(['*'], JSONB)),
            ))
        )
        return self.db_session.session.execute(query).scalars().first()

    def get_by_id(self, entry_id: str) -> Optional[KeyEntry]:
        """
        Fetches the key entry by its unique ID.
        """
        query = select(KeyEntry).where(KeyEntry.entry_id == entry_id)
        return self.db_session.session.execute(query).scalars().first()

    def get_by_org(self, organization: str) -> Optional[Sequence[KeyEntry]]:
        """
        Fetches all key entries for a given organization.
        """
        query = select(KeyEntry).where(KeyEntry.organization == organization)
        return self.db_session.session.execute(query).scalars().all()

    def create(self, organization: str, scope: list[str], pub_key: str, max_usage_level: str) -> KeyEntry:
        """
        Creates a new key entry.
        """
        entry = KeyEntry(
            organization=organization,
            scope=scope,
            key=pub_key,
            max_rid_usage=max_usage_level,
        )
        self.db_session.session.add(entry)

        return entry

    def update(self, entry_id: str, scope: list[str], pub_key: str, max_usage_level: str) -> Optional[KeyEntry]:
        """
        Updates an existing key entry.
        """
        entry = self.get_by_id(entry_id)
        if entry is None:
            raise ValueError("Key entry not found")

        entry.scope = scope # type: ignore
        entry.key = pub_key # type: ignore
        entry.max_rid_usage = max_usage_level # type: ignore
        self.db_session.session.add(entry)
        return entry
