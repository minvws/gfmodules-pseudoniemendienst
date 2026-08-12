from httpx import Auth
from app.db.entities.authorization import Authorization
import logging
import uuid
from datetime import datetime
from typing import List

from sqlalchemy import and_, func, insert, literal, or_, select, update, Exists, exists
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.orm import joinedload
from app.db.decorator import repository
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.repositories.repository_base import RepositoryBase
from app.models.oin import Oin

logger = logging.getLogger(__name__)


@repository(Authorization)
class AuthorizationRepository(RepositoryBase):
    def exists(self, organization_id: Oin, action: str, _object: str) -> bool:
        query = select(
            exists().where(
                and_(
                    Authorization.organization_id == organization_id.value,
                    Authorization.action == action,
                    Authorization.object == _object,
                )
            )
        )
        record_exists = self.db_session.session.scalar(query)
        print(record_exists)
        return record_exists
        stmt = select(
            exists().where(
                Authorization.organization_id == organization_id
                and Authorization.action == action
                and Authorization.object == _object
            )
        )
        record_exists = self.db_session.session.scalar(stmt)
        return record_exists
