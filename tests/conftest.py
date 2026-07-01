import os

os.environ["FASTAPI_CONFIG_PATH"] = "./app.test.conf"  # noqa

from app.config import get_config, set_config
from typing import Callable, Generator
import inject
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.models.auth.headers import AUTH_HEADER_X_GF_AUDIENCE, AUTH_HEADER_X_GF_OIN
from app.models.oin import Oin
from app.db.repositories.org_key_repository import OrganizationKeyRepository
from app.services.org_service import OrgService
from app.db.db import Database
from app.services.key_resolver import KeyResolver

import secrets
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def genkey(len: int) -> str:
    key_bytes = secrets.token_bytes(len)
    return base64.urlsafe_b64encode(key_bytes).decode("ascii")


@pytest.fixture
def test_public_key() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return public_key_pem.strip()


conf = get_config()
oprf_path = conf.oprf.server_key_file
if not os.path.exists(oprf_path):
    os.makedirs("secrets", exist_ok=True)
    with open(oprf_path, "w") as f:
        f.write(genkey(32))

if not conf.pseudonym.master_key:
    conf.pseudonym.master_key = genkey(32)
set_config(conf)


@pytest.fixture
def test_oin() -> Oin:
    return Oin("00000099000000001000")


@pytest.fixture
def test_other_oin() -> Oin:
    return Oin("00000099000000002000")


@pytest.fixture
def test_unknown_oin() -> Oin:
    return Oin("00000099000000003000")


@pytest.fixture
def test_audience() -> str:
    return "prs.service"


@pytest.fixture
def auth_headers(test_oin: Oin, test_audience: str) -> dict[str, str]:
    return {
        AUTH_HEADER_X_GF_OIN: test_oin.value,
        AUTH_HEADER_X_GF_AUDIENCE: test_audience,
    }


@pytest.fixture
def auth_headers_for_oin(test_audience: str) -> Callable[[str | Oin], dict[str, str]]:
    def auth_headers(oin: str | Oin) -> dict[str, str]:
        oin_value = oin.value if isinstance(oin, Oin) else oin
        return {
            AUTH_HEADER_X_GF_OIN: oin_value,
            AUTH_HEADER_X_GF_AUDIENCE: test_audience,
        }

    return auth_headers


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
