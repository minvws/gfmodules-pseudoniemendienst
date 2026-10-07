import logging
import random
import types
from collections.abc import Callable
from time import sleep
from typing import Any, TypeVar

import gfmodules.logging as gflog
from sqlalchemy import Engine, Result
from sqlalchemy.exc import DatabaseError, OperationalError, PendingRollbackError
from sqlalchemy.orm import Session
from typing_extensions import Self

from app.config import get_config
from app.db.models.base import Base
from app.db.repositories import repository_base
from app.logging.events import Log

logger = logging.getLogger(__name__)

T = TypeVar("T")


class DbSession:
    _engine: Engine
    _commit: bool

    def __init__(self, engine: Engine, commit: bool) -> None:
        self._engine = engine
        self._commit = commit

    def __enter__(self) -> Self:
        self.session = Session(self._engine, expire_on_commit=False)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        if exc_type is None and exc_val is None and self._commit:
            self.session.commit()
        self.session.close()

    def get_repository(
        self, repository_class: type["repository_base.TRepositoryBase_co"]
    ) -> "repository_base.TRepositoryBase_co":
        if issubclass(repository_class, repository_base.RepositoryBase):
            return repository_class(self)
        raise ValueError(f"No repository registered for model {repository_class}")

    def add(self, entry: Base) -> None:
        self._retry(self.session.add, entry)

    def delete(self, entry: Base) -> None:
        # database cascading will take care of the rest
        self._retry(self.session.delete, entry)

    def flush(self) -> None:
        self._retry(self.session.flush)

    def commit(self) -> None:
        self._retry(self.session.commit)

    def rollback(self) -> None:
        self._retry(self.session.rollback)

    def query(self, *entities: Any) -> Any:
        return self._retry(self.session.query, *entities)

    def execute(self, stmt: Any) -> Result[Any]:
        return self._retry(self.session.execute, stmt)

    def begin(self) -> Any:
        return self._retry(self.session.begin)

    def _retry(self, f: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        backoff = get_config().database.retry_backoff
        attempt = 0

        while True:
            error: Exception
            try:
                return f(*args, **kwargs)
            except PendingRollbackError as e:
                logger.warning("retrying operation due to PendingRollbackError: %s", e)
                self.session.rollback()
                error = e
            except OperationalError as e:
                logger.warning("retrying operation due to OperationalError: %s", e)
                error = e
            except DatabaseError as e:
                logger.warning(
                    "operation failed with a non-retryable DatabaseError: %s", e
                )
                raise
            except Exception as e:
                logger.warning("generic Exception during operation: %s", e)
                raise

            attempt += 1
            if len(backoff) == 0:
                logger.error("operation failed after all retries")
                gflog.emit(
                    logger,
                    Log.SYS_DB_CONNECTION_FAILED,
                    "Database connection lost: giving up after all retries",
                    fields={
                        "datastore": "prs-database",
                        "error_type": type(error).__name__,
                        "retry_attempt": attempt,
                    },
                )
                raise DatabaseError(
                    "Operation failed after all retries", None, BaseException()
                )

            gflog.emit(
                logger,
                Log.SYS_DB_CONNECTION_FAILED,
                "Database connection lost, retrying",
                fields={
                    "datastore": "prs-database",
                    "error_type": type(error).__name__,
                    "retry_attempt": attempt,
                    "backoff_seconds": backoff[0],
                },
            )
            sleep(backoff[0] + random.uniform(0, 0.1))
            backoff = backoff[1:]
