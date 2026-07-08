import logging

from sqlalchemy import MetaData, StaticPool, create_engine, text
from sqlalchemy.orm import Session

from app.db.entities.base import Base
from app.db.session import DbSession

logger = logging.getLogger(__name__)


class Database:
    def __init__(
        self,
        dsn: str,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_pre_ping: bool = False,
        pool_recycle: int = 3600,
    ):
        try:
            if "sqlite://" in dsn:
                self.engine = create_engine(
                    dsn,
                    connect_args={"check_same_thread": False},
                    # This + static pool is needed for sqlite in-memory tables
                    poolclass=StaticPool,
                    echo=False,
                )
            else:
                self.engine = create_engine(
                    dsn,
                    echo=False,
                    pool_size=pool_size,
                    max_overflow=max_overflow,
                    pool_pre_ping=pool_pre_ping,
                    pool_recycle=pool_recycle,
                )
        except BaseException as e:
            logger.exception("error while connecting to database")
            raise e

    def generate_tables(self) -> None:
        logger.info("generating tables...")
        Base.metadata.create_all(self.engine)

    def truncate_tables(self) -> None:
        logger.info("truncating all tables...")
        try:
            metadata = MetaData()
            metadata.reflect(bind=self.engine)
            with Session(self.engine) as session:
                for table in reversed(metadata.sorted_tables):
                    session.execute(text(f"DELETE FROM {table.name}"))
                session.commit()
            logger.info("all tables truncated successfully.")
        except Exception as e:
            logger.exception("error while truncating tables")
            raise e

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

    def get_db_session(self) -> DbSession:
        return DbSession(self.engine)
