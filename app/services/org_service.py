import uuid

from app.db.db import Database
from app.db.entities.organization import Organization
from app.db.repositories.org_repository import OrgRepository
from app.rid import RidUsage
import logging

logger = logging.getLogger(__name__)

class OrgService:
    def __init__(self, db: Database) -> None:
        self.__db = db

    def get_by_ura(self, ura: str) -> Organization|None:
        with self.__db.get_db_session() as session:
            repo = session.get_repository(OrgRepository)
            return repo.get_by_ura(ura)

    def create(self, ura: str, name: str, max_key_usage: RidUsage) -> Organization:
        with self.__db.get_db_session() as session:
            try:
                repo = session.get_repository(OrgRepository)
                org = repo.create(ura, name, max_key_usage)
                session.commit()
            except Exception as e:
                session.rollback()
                logger.error("failed to create org (ura=%r): %s", ura, e)
                raise

            return org

    def update(self, org_id: uuid.UUID, name: str, max_key_usage: RidUsage) -> Organization|None:
        with self.__db.get_db_session() as session:
            try:
                repo = session.get_repository(OrgRepository)
                org = repo.update(org_id, name, max_key_usage)
                session.commit()
            except Exception as e:
                session.rollback()
                logger.error("failed to update org with id %s: %s", org_id, e)
                raise
            return org

    def delete(self, org_id: uuid.UUID) -> bool:
        with self.__db.get_db_session() as session:
            try:
                repo = session.get_repository(OrgRepository)
                success = repo.delete(org_id)
                session.commit()
            except Exception as e:
                session.rollback()
                logger.error("failed to delete org with id %s: %s", org_id, e)
                raise
            return success

