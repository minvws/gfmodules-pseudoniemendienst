import logging
import uuid

from app.db.db import Database
from app.db.entities.organization_key import OrganizationPublicKey
from app.db.repositories.authorization_repository import AuthorizationRepository
from app.db.repositories.organization_public_key_repository import (
    OrganizationPublicKeyRepository,
)
from app.models.oin import Oin

logger = logging.getLogger(__name__)


class AuthorizationService:
    def __init__(self, db: Database):
        self.db = db

    def exists(self, organization_id: Oin, action: str, _object: str) -> bool:
        with self.db.get_db_session() as session:
            return session.get_repository(AuthorizationRepository).exists(
                organization_id, action, _object
            )

    def get_by_org_and_domain(
        self, org_id: Oin, domain: str
    ) -> OrganizationPublicKey | None:
        with self.db.get_db_session() as session:
            return session.get_repository(
                OrganizationPublicKeyRepository
            ).get_by_org_and_domain(org_id, domain)

    def delete(self, key_id: uuid.UUID, organization_id: Oin) -> bool:
        with self.db.get_db_session() as session:
            repository = session.get_repository(OrganizationPublicKeyRepository)
            deleted = repository.delete(key_id, organization_id)
            if not deleted:
                entry = repository.get_by_id(key_id)
                if entry is not None and entry.organization_id != organization_id:
                    logger.warning(
                        "caller org %s attempted to delete key %s owned by org %s",
                        organization_id,
                        key_id,
                        entry.organization_id,
                    )

                return False

            session.commit()
            return True
