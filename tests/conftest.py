from typing import Generator
import inject
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import set_config
from app.db.repositories.org_key_repository import OrganizationKeyRepository
from app.services.org_service import OrgService
from test_config import get_test_config
set_config(get_test_config())

from app.application import create_fastapi_app  # noqa: E402
from app.db.db import Database # noqa: E402
from app.services.key_resolver import KeyResolver # noqa: E402

@pytest.fixture
def app() -> Generator[FastAPI, None, None]:
    from app.container import container_config
    set_config(get_test_config())
    # Configure the injector for each test, clear if already configured
    if inject.is_configured():
        inject.configure(container_config, clear=True)
    else:
        inject.configure(container_config)
    app = create_fastapi_app()
    yield app
    inject.clear()


@pytest.fixture
def database() -> Database:
    set_config(get_test_config())
    try:
        # first use the database from the injector
        db = inject.instance(Database)
        db.generate_tables()
        db.truncate_tables()
        return db
    except inject.InjectorException:
        pass
    db = Database(dsn=get_test_config().database.dsn)
    db.generate_tables()
    db.truncate_tables()
    return db

@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)

@pytest.fixture
def key_resolver(database: Database) -> KeyResolver:
    return KeyResolver(database)

@pytest.fixture
def repo(key_resolver: KeyResolver) -> OrganizationKeyRepository:
    with key_resolver.db.get_db_session() as session:
        return session.get_repository(OrganizationKeyRepository)

@pytest.fixture
def org_service(database: Database) -> OrgService:
    return OrgService(database)
