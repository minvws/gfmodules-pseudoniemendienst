import logging

from sqlalchemy import StaticPool, create_engine, text
from sqlalchemy.orm import Session

from app.config import ConfigDatabase
from app.db.models.base import Base
from app.db.session import DbSession

logger = logging.getLogger(__name__)


class Database:
    _config_database: ConfigDatabase

    def __init__(self, config_database: ConfigDatabase):
        self._config_database = config_database

        try:
            if "sqlite://" in config_database.dsn.get_secret_value():
                self.engine = create_engine(
                    config_database.dsn.get_secret_value(),
                    connect_args={"check_same_thread": False},
                    # This + static pool is needed for sqlite in-memory tables
                    poolclass=StaticPool,
                    echo=False,
                )
            else:
                self.engine = create_engine(
                    config_database.dsn.get_secret_value(),
                    echo=False,
                    pool_size=config_database.pool_size,
                    max_overflow=config_database.max_overflow,
                    pool_pre_ping=config_database.pool_pre_ping,
                    pool_recycle=config_database.pool_recycle,
                )
        except BaseException:
            logger.exception("error while connecting to database")
            raise

    def generate_tables(self) -> None:
        logger.info("generating tables...")
        Base.metadata.create_all(self.engine)

    def health_error(self) -> str | None:
        try:
            with Session(self.engine) as session:
                session.execute(text("SELECT 1"))
            return None
        except Exception as e:  # noqa: BLE001 Every exception here may result in a not healthy result
            logger.info("database is not healthy: %s", e)
            return str(e)

    def is_healthy(self) -> bool:
        return self.health_error() is None

    def get_db_session(self, commit: bool = False) -> DbSession:
        return DbSession(self.engine, commit)
