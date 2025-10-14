from app.db.db import Database
from app.db.entities.organization import Organization
from app.db.repositories.org_repository import OrgRepository
from app.rid import RidUsage


class OrgService:
    def __init__(self, db: Database) -> None:
        self.__db = db

    def get_by_ura(self, ura: str) -> Organization|None:
        with self.__db.get_db_session() as session:
            repo = session.get_repository(OrgRepository)
            return repo.get_by_ura(ura)

    def create(self, ura: str, name: str, max_key_usage: RidUsage) -> Organization:
        with self.__db.get_db_session() as session:
            repo = session.get_repository(OrgRepository)
            org = repo.create(ura, name, max_key_usage)
            session.commit()
            return org

    def update(self, org_id: str, name: str, max_key_usage: RidUsage) -> Organization|None:
        with self.__db.get_db_session() as session:
            repo = session.get_repository(OrgRepository)
            org = repo.update(org_id, name, max_key_usage)
            session.commit()
            return org

    def delete(self, org_id: str) -> bool:
        with self.__db.get_db_session() as session:
            repo = session.get_repository(OrgRepository)
            success = repo.delete(org_id)
            session.commit()
            return success

