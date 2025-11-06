
import os

os.environ["FASTAPI_CONFIG_PATH"] = "./app.test.conf" # noqa

from app.config import get_config, set_config
from typing import Generator
import inject
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.db.repositories.org_key_repository import OrganizationKeyRepository
from app.services.org_service import OrgService
from app.db.db import Database
from app.services.key_resolver import KeyResolver

import secrets
import base64

def genkey(len: int) -> str:
        key_bytes = secrets.token_bytes(len)
        return base64.urlsafe_b64encode(key_bytes).decode('ascii')

conf = get_config()
oprf_path = conf.oprf.server_key_file
if not os.path.exists(oprf_path):
    os.makedirs("secrets", exist_ok=True)
    with open(oprf_path, "w") as f:
        f.write(genkey(32))

if conf.pseudonym.hmac_key is None:
    conf.pseudonym.hmac_key = genkey(32)
if conf.pseudonym.aes_key is None:
    conf.pseudonym.aes_key = genkey(32)
if conf.pseudonym.rid_aes_key is None:
    conf.pseudonym.rid_aes_key = genkey(32)
set_config(conf)

@pytest.fixture
def app() -> Generator[FastAPI, None, None]:
    from app.application import create_fastapi_app
    from app.container import container_config
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
    try:
        # first use the database from the injector
        db = inject.instance(Database)
        db.generate_tables()
        db.truncate_tables()
        return db
    except inject.InjectorException:
        pass
    db = Database(dsn=get_config().database.dsn)
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

