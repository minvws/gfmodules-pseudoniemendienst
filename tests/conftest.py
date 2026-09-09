import logging
import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import text

from app.db.models import HsmKeyVersionEntity, OrganizationEntity
from app.db.models.personal_id_type import PersonalIdTypeEntity
from app.db.repositories.personal_id_type_repository import PersonalIdTypeRepository
from app.db.session import DbSession
from app.enums.personal_id_type import PersonalIdType
from app.models.oin import Oin
from app.services.organization_public_key_service import OrganizationPublicKeyService

os.environ["FASTAPI_CONFIG_PATH"] = "./app.test.conf"

import base64
import secrets
from collections.abc import Callable, Generator
from datetime import datetime, timezone

import inject
import pytest
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from pydantic import SecretStr
from starlette.testclient import TestClient

from app.config import get_config, set_config
from app.db.db import Database


def genkey(len: int) -> str:
    key_bytes = secrets.token_bytes(len)
    return base64.urlsafe_b64encode(key_bytes).decode("ascii")


conf = get_config()
oprf_path = conf.oprf.server_key_file
if not os.path.exists(oprf_path):
    os.makedirs("secrets", exist_ok=True)
    with open(oprf_path, "w") as f:
        f.write(genkey(32))

if not conf.pseudonym.master_key.get_secret_value():
    conf.pseudonym.master_key = SecretStr(genkey(32))
set_config(conf)


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def record_logs() -> Generator[Callable[[str], list[logging.LogRecord]], None, None]:
    """Attach a recording handler to a specific module logger and return its records.

    The logging dictConfig neither propagates ``app.*`` records to the root logger
    (so caplog misses them) nor configures the module loggers themselves, so a
    handler attached there survives ``create_fastapi_app`` re-running dictConfig.
    """
    attached: list[tuple[logging.Logger, RecordingHandler]] = []

    def _attach(logger_name: str) -> list[logging.LogRecord]:
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
def app(database: Database) -> Generator[FastAPI, None, None]:
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
    except inject.InjectorException:
        db = Database(get_config().database)
    with db.get_db_session() as session:
        session.execute(
            text("CREATE SCHEMA IF NOT EXISTS admin; CREATE SCHEMA IF NOT EXISTS prs;")
        )
        session.commit()
    db.generate_tables()
    db.truncate_tables()
    with db.get_db_session(commit=True) as session:
        for p in PersonalIdType:
            session.add(PersonalIdTypeEntity(name=p))
    return db


@pytest.fixture()
def db_session(database: Database) -> Generator[DbSession, Any, None]:
    with database.get_db_session() as session:
        yield session


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture
def organization_public_key_service(database: Database) -> OrganizationPublicKeyService:
    return OrganizationPublicKeyService(database)


@pytest.fixture
def valid_organization_id() -> Oin:
    return Oin("00000099000000002000")


@pytest.fixture
def valid_organization_id_2() -> Oin:
    return Oin("00000099000000003000")


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
) -> dict[str, str]:
    return {
        "x-gf-sub": valid_organization_id.value,
        "x-gf-act-sub": valid_client_organization_id.value,
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": "prs.service",
    }


@pytest.fixture()
def personal_id_type_repository(db_session: DbSession) -> PersonalIdTypeRepository:
    return PersonalIdTypeRepository(db_session=db_session)


@pytest.fixture()
def persisted_organization_2(
    db_session: DbSession,
    personal_id_type_repository: PersonalIdTypeRepository,
    valid_organization_id_2: Oin,
) -> OrganizationEntity:
    return create_organization(
        db_session, personal_id_type_repository, valid_organization_id_2
    )


@pytest.fixture()
def persisted_organization(
    db_session: DbSession,
    personal_id_type_repository: PersonalIdTypeRepository,
    valid_organization_id: Oin,
) -> OrganizationEntity:
    return create_organization(
        db_session, personal_id_type_repository, valid_organization_id
    )


def create_organization(
    db_session: DbSession,
    personal_id_type_repository: PersonalIdTypeRepository,
    external_id: Oin,
) -> OrganizationEntity:
    org = (
        db_session.session.query(OrganizationEntity)
        .filter(OrganizationEntity.external_id == external_id.value)
        .first()
    )
    if org:
        return org
    personal_ids = personal_id_type_repository.get_many([PersonalIdType.OPRF])
    assert len(personal_ids) == 1
    org = OrganizationEntity(
        external_id=external_id,
        name="test_org",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=list(personal_ids),
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(timezone.utc))
        ],
    )
    db_session.add(org)
    db_session.commit()
    return org


def generate_rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return private_key_pem, public_key_pem


def create_signed_jws(private_key_pem: str, oin: Oin) -> str:
    key = JWK.from_pem(private_key_pem.encode())
    claims = {
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "oin": oin.value,
    }
    header = {"alg": "RS256", "jwk": key.export_public(as_dict=True)}

    token = JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return str(token.serialize())


def setup_org_and_key(
    organization_public_key_service: OrganizationPublicKeyService,
    organization: OrganizationEntity,
    domains: list[str],
) -> str:
    private_key_pem, _ = generate_rsa_keypair()
    organization_public_key_service.create(
        organization.external_id,
        domains=domains,
        raw_jws=create_signed_jws(private_key_pem, organization.external_id),
    )
    return private_key_pem
