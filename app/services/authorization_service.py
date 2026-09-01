import logging

from app.db.db import Database
from app.db.repositories.organization_repository import OrganizationRepository
from app.enums.personal_id_type import PersonalIdType
from app.models.oin import Oin

logger = logging.getLogger(__name__)


class AuthorizationService:
    def __init__(self, db: Database):
        self.db = db

    def validate_allowed_to_request(
        self, organization_id: Oin, personal_id_type: PersonalIdType
    ) -> None:
        with self.db.get_db_session() as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(organization_id)
            if not org:
                raise Exception("TODO NICE EXCEPTION, unauthorized to do this request")
            if not personal_id_type in [
                rpit.name for rpit in org.request_personal_id_types
            ]:
                raise Exception("TODO NICE EXCEPTION, unauthorized to do this request")

    def validate_allowed_to_receive(
        self, organization_id: Oin, personal_id_type: PersonalIdType
    ) -> None:
        with self.db.get_db_session() as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(organization_id)
            if not org:
                raise Exception("TODO NICE EXCEPTION, unauthorized to do this request")
            if not personal_id_type in [
                rpit.name for rpit in org.receive_personal_id_types
            ]:
                raise Exception("TODO NICE EXCEPTION, unauthorized to do this request")
