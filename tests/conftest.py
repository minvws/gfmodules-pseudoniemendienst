import logging
import os

from app.models.oin import Oin

os.environ["FASTAPI_CONFIG_PATH"] = "./app.test.conf"  # noqa

import base64
import secrets
from typing import Callable, Dict, Generator, List

import inject
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import get_config, set_config
from app.db.db import Database
from app.db.repositories.org_key_repository import OrganizationKeyRepository
from app.services.key_resolver import KeyResolver
from app.services.org_service import OrgService


def genkey(len: int) -> str:
    key_bytes = secrets.token_bytes(len)
    return base64.urlsafe_b64encode(key_bytes).decode("ascii")


conf = get_config()
oprf_path = conf.oprf.server_key_file
if not os.path.exists(oprf_path):
    os.makedirs("secrets", exist_ok=True)
    with open(oprf_path, "w") as f:
        f.write(genkey(32))

if not conf.pseudonym.master_key:
    conf.pseudonym.master_key = genkey(32)
set_config(conf)


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def record_logs() -> Generator[Callable[[str], List[logging.LogRecord]], None, None]:
    """Attach a recording handler to a specific module logger and return its records.

    The logging dictConfig neither propagates ``app.*`` records to the root logger
    (so caplog misses them) nor configures the module loggers themselves, so a
    handler attached there survives ``create_fastapi_app`` re-running dictConfig.
    """
    attached: List[tuple[logging.Logger, RecordingHandler]] = []

    def _attach(logger_name: str) -> List[logging.LogRecord]:
        handler = RecordingHandler()
        target = logging.getLogger(logger_name)
        target.addHandler(handler)
        attached.append((target, handler))
        return handler.records

    try:
        yield _attach
    finally:
        for target, handler in attached:
            target.removeHandler(handler)


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


@pytest.fixture
def valid_organization_id() -> Oin:
    return Oin("00000099000000002000")


@pytest.fixture
def valid_client_organization_id() -> Oin:
    return Oin("00000099000000001000")


@pytest.fixture
def valid_client_common_name() -> str:
    return "client_common_name"


@pytest.fixture
def valid_headers(
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
) -> Dict[str, str]:
    return {
        "x-gf-sub": valid_organization_id.value,
        "x-gf-act-sub": valid_client_organization_id.value,
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": "prs.service",
    }
