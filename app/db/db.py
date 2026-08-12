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

    def truncate_tables(self) -> None:
        logger.info("truncating all tables...")
        try:
            metadata = Base.metadata
            metadata.reflect(bind=self.engine)
            with Session(self.engine) as session:
                for table in reversed(metadata.sorted_tables):
                    session.execute(text(f"DELETE FROM {table.schema}.{table.name}"))
                session.commit()
            logger.info("all tables truncated successfully.")
        except Exception:
            logger.exception("error while truncating tables")
            raise

    def health_error(self) -> str | None:
        """
        Check if the database is healthy

        :return: None if the database is healthy, the error detail otherwise
        """
        try:
            with Session(self.engine) as session:
                session.execute(text("SELECT 1"))
            return None
        except Exception as e:
            logger.info("database is not healthy: %s", e)
            return str(e)

    def is_healthy(self) -> bool:
        """
        Check if the database is healthy

        :return: True if the database is healthy, False otherwise
        """
        return self.health_error() is None

    def get_db_session(self, commit: bool = False) -> DbSession:
        return DbSession(self.engine, commit)
