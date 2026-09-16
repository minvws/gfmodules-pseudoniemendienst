from typing import TypeVar

from app.db import session


class RepositoryBase:
    """
    Base class for all repositories, providing common functionality.
    """

    def __init__(self, db_session: session.DbSession):
        self.db_session = db_session


TRepositoryBase_co = TypeVar("TRepositoryBase_co", bound=RepositoryBase, covariant=True)
