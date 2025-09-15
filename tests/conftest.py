import os
from typing import Generator, Type, Protocol, TypeVar, Callable, Any

import pytest
from contextlib import contextmanager

from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import sessionmaker, Session, clear_mappers

from app.db.entities.base import Base
from app.db.session import DbSession

try:
    from testcontainers.postgres import PostgresContainer
    HAVE_TESTCONTAINERS = True
except Exception:
    HAVE_TESTCONTAINERS = False

from app.db.repositories.key_entry_repository import KeyEntryRepository

class RepositoryBaseProtocol(Protocol):
    def __init__(self, _db_session: "DbSessionWrapper") -> None: ...

RepoT = TypeVar("RepoT", bound=RepositoryBaseProtocol)  # codespell:ignore

class DbSessionWrapper:
    session: Session

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_repository(self, repo_cls: Type[RepoT]) -> RepoT:  # codespell:ignore
        return repo_cls(self)

    # def session(self) -> :
    #     return self.session

    def commit(self) -> None:
        self.session.commit()

class FakeDatabase:
    _session_factory: Callable[[], Session]

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    @contextmanager
    def get_db_session(self) -> Generator[DbSessionWrapper, None, None]:
        session = self._session_factory()
        try:
            # yield DbSession(session)
            yield DbSessionWrapper(session)
        finally:
            session.close()

@pytest.fixture(scope="session")
def pg_url() -> Generator[str, None, None]:
    """
    Spins up a temp PostgreSQL with testcontainers.
    Set TEST_PG_URL to reuse a local Postgres if you prefer.
    """
    env_url = os.getenv("TEST_PG_URL")
    if env_url:
        yield env_url
        return

    if not HAVE_TESTCONTAINERS:
        pytest.skip("testcontainers not available and TEST_PG_URL not set")

    with PostgresContainer("postgres:16-alpine", driver="psycopg") as pg:
        yield pg.get_connection_url()

@pytest.fixture(scope="session")
def engine(pg_url: str) -> Generator[Engine, None, None]:
    eng = create_engine(pg_url, future=True)
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    clear_mappers()

@pytest.fixture
def session(engine: Engine) -> Generator[Session, None, None]:
    session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True, expire_on_commit=False)
    sess = session_local()
    try:
        yield sess
        sess.rollback()
    finally:
        sess.close()

@pytest.fixture
def db_wrap(session: Session) -> DbSessionWrapper:
    return DbSessionWrapper(session)

@pytest.fixture
def repo(db_wrap: DbSession) -> KeyEntryRepository:
    return KeyEntryRepository(db_wrap)

@pytest.fixture
def fake_db(session: Any) -> FakeDatabase:
    session_local = sessionmaker(bind=session.get_bind(), autoflush=False, autocommit=False, future=True, expire_on_commit=False)
    return FakeDatabase(session_local)
