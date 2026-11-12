import base64
import json
import logging
import secrets
from collections.abc import Callable, Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import gfmodules.logging as gflog
import pyoprf
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from gfmodules.logging import ConfigLogging
from gfmodules.logging.testing import reset_for_tests
from jwcrypto import jwe, jws
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from sqlalchemy import select, text
from starlette.testclient import TestClient

from app.application import setup_fastapi
from app.config import set_config
from app.container import (
    get_auth_headers_service,
    get_hsm_key_version_service,
    get_irreversible_pseudonym_service,
    get_jwe_token_service,
    get_jwt_signing_service,
    get_oprf_service,
    get_organization_public_key_service,
    get_reversible_pseudonym_service,
    get_saml_service_client,
)
from app.db.db import Database
from app.db.models import HsmKeyVersionEntity, OrganizationEntity
from app.db.models.base import Base
from app.db.models.personal_id_type import PersonalIdTypeEntity
from app.db.repositories.hsm_key_version_repository import HsmKeyVersionRepository
from app.db.repositories.organization_public_key_repository import (
    OrganizationPublicKeyRepository,
)
from app.db.repositories.organization_repository import OrganizationRepository
from app.db.session import DbSession
from app.enums.personal_id_type import PersonalIdType
from app.logging.events import Log
from app.models.auth.data import AuthorizationScope
from app.models.auth.headers import AuthHeaders
from app.models.oin import Oin
from app.models.personal_id import PersonalId
from app.services.auth.header import AuthHeaderService
from app.services.authorization_service import AuthorizationService
from app.services.hsm.client import HsmClient
from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.http_service import HttpService
from app.services.irreversible.keys import (
    HsmIrreversibleKeyOperations,
    IrreversibleKeyLabel,
    LocalIrreversibleKeyOperations,
)
from app.services.irreversible.service import IrreversiblePseudonymService
from app.services.jwe_token import JweTokenService
from app.services.jwt_signer import HsmJwtSigner, JwtSigningService, LocalJwtSigner
from app.services.oprf.evaluators import HsmOprfEvaluator, LocalOprfEvaluator
from app.services.oprf.oprf_service import OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.keys import (
    HsmReversibleKeyOperations,
    LocalReversibleKeyOperations,
)
from app.services.reversible.service import ReversiblePseudonymService
from app.services.saml.client import SamlServiceClient
from tests.test_config import get_test_config

JWT_ISSUER = get_test_config().jwt_signing.issuer


def blinded_input() -> str:
    _, blinded = pyoprf.blind(b"personal-id")
    return base64.urlsafe_b64encode(blinded).decode("ascii")


def genkey(len: int) -> str:
    key_bytes = secrets.token_bytes(len)
    return base64.urlsafe_b64encode(key_bytes).decode("ascii")


@pytest.fixture(autouse=True)
def logging_catalogue() -> Generator[None, None, None]:
    gflog.configure(
        config=ConfigLogging(console_streams=["debug"], access_logs=True),
        loglevel="DEBUG",
        catalogue=Log,
    )
    try:
        yield
    finally:
        reset_for_tests()


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


@pytest.fixture(scope="session")
def database() -> Generator[Database, None, None]:
    """Session-wide engine, schemas and tables — created once per run.
    SHARED, DIRTY: guarantees nothing about table contents. Only this
    file's session-scoped service and `app` fixtures may depend on it."""
    config = get_test_config()
    set_config(config)
    db = Database(config_database=config.database)
    with db.get_db_session() as session:
        session.execute(
            text("CREATE SCHEMA IF NOT EXISTS admin; CREATE SCHEMA IF NOT EXISTS prs;")
        )
        session.commit()

    db.generate_tables()
    yield db
    db.engine.dispose()


def _reset_database(db: Database) -> None:
    """Truncate every table (RESTART IDENTITY CASCADE) and reseed the
    personal-id types. The physical reset behind the autouse isolation."""

    with db.get_db_session() as session:
        for table in reversed(Base.metadata.sorted_tables):
            name = (
                f'"{table.schema}"."{table.name}"'
                if table.schema
                else f'"{table.name}"'
            )
            session.execute(text(f"TRUNCATE {name} RESTART IDENTITY CASCADE"))
        session.commit()

    with db.get_db_session(commit=True) as session:
        for p in PersonalIdType:
            session.add(PersonalIdTypeEntity(name=p))


@pytest.fixture(autouse=True)
def db_isolation(
    request: pytest.FixtureRequest, database: Database
) -> Generator[None, None, None]:
    """Every test starts against a truncated, seeded database.

    Autouse on purpose: with a session-scoped app sharing physical tables,
    any opt-in isolation model silently leaks state between tests. Runs
    before all other function-scoped fixtures, so data-setup fixtures
    (persisted_organization et al.) always insert into a clean world.

    Escape hatch for suites where per-test truncate proves too costly:
    mark pure unit-test directories with @pytest.mark.no_db.
    """
    if request.node.get_closest_marker("no_db"):
        yield
        return

    _reset_database(database)
    yield


@pytest.fixture
def db_session(database: Database) -> Generator[DbSession, Any, None]:
    """Open session on the shared engine. Table contents are guaranteed
    clean by `db_isolation` (autouse) — this fixture just hands out sessions
    for direct repository work."""
    with database.get_db_session() as session:
        yield session


@pytest.fixture
def organization_repository(db_session: DbSession) -> OrganizationRepository:
    return OrganizationRepository(db_session)


@pytest.fixture
def organization_public_key_repository(
    db_session: DbSession,
) -> OrganizationPublicKeyRepository:
    return OrganizationPublicKeyRepository(db_session)


@pytest.fixture
def hsm_key_version_repository(db_session: DbSession) -> HsmKeyVersionRepository:
    return HsmKeyVersionRepository(db_session)


@pytest.fixture(scope="session")
def hsm_key_version_service(database: Database) -> HsmKeyVersionService:
    return HsmKeyVersionService(database)


@pytest.fixture(scope="session")
def expected_audiences() -> list[str]:
    config = get_test_config()
    return config.authorization_headers.expected_audiences


@pytest.fixture(scope="session")
def auth_headers_service(expected_audiences: list[str]) -> AuthHeaderService:
    return AuthHeaderService(expected_audiences=expected_audiences)


@pytest.fixture(scope="session")
def http_service() -> HttpService:
    config = get_test_config()
    assert config.hsm.url is not None
    return HttpService(endpoint=config.hsm.url, timeout=config.hsm.timeout)


@pytest.fixture(scope="session")
def hsm_client(http_service: HttpService) -> HsmClient:
    return HsmClient(http_service)


@pytest.fixture(scope="session")
def authorization_service(database: Database) -> AuthorizationService:
    return AuthorizationService(database)


@pytest.fixture(scope="session")
def organization_public_key_service(database: Database) -> OrganizationPublicKeyService:
    return OrganizationPublicKeyService(database)


@pytest.fixture(scope="session")
def local_oprf_evaluator() -> LocalOprfEvaluator:
    config = get_test_config()
    return LocalOprfEvaluator(
        server_key=base64.urlsafe_b64decode(
            config.local_keys.master_key.get_secret_value()
        )
    )


@pytest.fixture(scope="session")
def hsm_oprf_evaluator(
    hsm_client: HsmClient, hsm_key_version_service: HsmKeyVersionService
) -> HsmOprfEvaluator:
    return HsmOprfEvaluator(
        client=hsm_client, hsm_key_version_service=hsm_key_version_service
    )


@pytest.fixture(scope="session")
def oprf_service(hsm_oprf_evaluator: HsmOprfEvaluator) -> OprfService:
    return OprfService(hsm_oprf_evaluator)


@pytest.fixture(scope="session")
def local_oprf_service(
    local_oprf_evaluator: LocalOprfEvaluator, jwe_token_service: JweTokenService
) -> OprfService:
    return OprfService(local_oprf_evaluator, jwe_token_service)


@pytest.fixture(scope="session")
def saml_service_client() -> SamlServiceClient:
    config = get_test_config()
    assert config.saml_service.url is not None
    http_service = HttpService(
        endpoint=config.saml_service.url, timeout=config.saml_service.timeout
    )
    return SamlServiceClient(http_service)


@pytest.fixture(scope="session")
def irreversible_key_label(valid_organization_id: Oin) -> IrreversibleKeyLabel:
    return IrreversibleKeyLabel(valid_organization_id, 1)


@pytest.fixture(scope="session")
def local_irreversible_key_operations() -> LocalIrreversibleKeyOperations:
    config = get_test_config()
    return LocalIrreversibleKeyOperations(
        master_key=base64.urlsafe_b64decode(
            config.local_keys.master_key.get_secret_value().encode()
        )
    )


@pytest.fixture(scope="session")
def hsm_irreversible_key_operations(
    hsm_client: HsmClient,
) -> HsmIrreversibleKeyOperations:
    return HsmIrreversibleKeyOperations(hsm_client)


@pytest.fixture(scope="session")
def irreversible_pseudonym_service(
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
) -> IrreversiblePseudonymService:
    return IrreversiblePseudonymService(
        keys=hsm_irreversible_key_operations, key_versions=hsm_key_version_service
    )


@pytest.fixture(scope="session")
def local_irreversible_pseudonym_service(
    local_irreversible_key_operations: LocalIrreversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
) -> IrreversiblePseudonymService:
    return IrreversiblePseudonymService(
        keys=local_irreversible_key_operations, key_versions=hsm_key_version_service
    )


@pytest.fixture(scope="session")
def local_reversible_key_operations() -> LocalReversibleKeyOperations:
    config = get_test_config()
    return LocalReversibleKeyOperations(
        master_key=base64.urlsafe_b64decode(
            config.local_keys.master_key.get_secret_value().encode()
        )
    )


@pytest.fixture(scope="session")
def hsm_reversible_key_operations(hsm_client: HsmClient) -> HsmReversibleKeyOperations:
    return HsmReversibleKeyOperations(hsm_client)


@pytest.fixture(scope="session")
def reversible_pseudonym_service(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
) -> ReversiblePseudonymService:
    return ReversiblePseudonymService(
        keys=hsm_reversible_key_operations, key_versions=hsm_key_version_service
    )


@pytest.fixture(scope="session")
def local_reversible_pseudonym_service(
    local_reversible_key_operations: LocalReversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
) -> ReversiblePseudonymService:
    return ReversiblePseudonymService(
        keys=local_reversible_key_operations, key_versions=hsm_key_version_service
    )


@pytest.fixture(scope="session")
def hsm_key_cleanup_service(
    hsm_oprf_evaluator: HsmOprfEvaluator,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
) -> HsmKeyCleanupService:
    return HsmKeyCleanupService(
        oprf_keys=hsm_oprf_evaluator,
        irreversible_keys=hsm_irreversible_key_operations,
        reversible_keys=hsm_reversible_key_operations,
        version_service=hsm_key_version_service,
    )


@pytest.fixture(scope="session")
def auth_headers(
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    expected_audiences: list[str],
) -> AuthHeaders:
    return AuthHeaders(
        organization_id=valid_client_organization_id,
        client_organization_id=valid_organization_id,
        client_organization_common_name=valid_client_common_name,
        audience="".join(expected_audiences),
        scope=AuthorizationScope.OPRF_PSEUDONYM.value,  # type: ignore
    )


@pytest.fixture(scope="session")
def local_jwt_signer() -> LocalJwtSigner:
    private_key_pem, _ = generate_rsa_keypair()
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey), "Expected RSA private key"
    signer = LocalJwtSigner(private_key, "test-key")
    return signer


@pytest.fixture(scope="session")
def hsm_jwt_signer() -> HsmJwtSigner:
    mock_hsm = MagicMock(spec=HsmClient)
    _, public_key_pem = generate_rsa_keypair()
    mock_hsm.public_key_pem.return_value = public_key_pem
    mock_hsm.sign_rsa_pss_sha256.return_value = b"dummy-signature"

    return HsmJwtSigner(mock_hsm, "test-label")


@pytest.fixture(scope="session")
def jwt_signing_service() -> JwtSigningService:
    """Create a test JWT signing service with a local RSA key."""
    private_key_pem, _ = generate_rsa_keypair()
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey), "Expected RSA private key"
    signer = LocalJwtSigner(private_key, "test-key")
    return JwtSigningService(issuer=JWT_ISSUER, active=signer, signers=(signer,))


@pytest.fixture(scope="session")
def jwe_token_service(jwt_signing_service: JwtSigningService) -> JweTokenService:
    return JweTokenService(jwt_signing_service)


@pytest.fixture(scope="session")
def app(
    database: Database,
    local_irreversible_pseudonym_service: IrreversiblePseudonymService,
    local_reversible_pseudonym_service: ReversiblePseudonymService,
    hsm_key_version_service: HsmKeyVersionService,
    auth_headers_service: AuthHeaderService,
    organization_public_key_service: OrganizationPublicKeyService,
    local_oprf_service: OprfService,
    saml_service_client: SamlServiceClient,
    jwt_signing_service: JwtSigningService,
    jwe_token_service: JweTokenService,
    tmp_path_factory: pytest.TempPathFactory,
) -> FastAPI:
    local_config = get_test_config()
    local_config.jwt_signing.enabled = True
    priv, _ = generate_rsa_keypair()
    temp_signing_files = tmp_path_factory.mktemp("secrets") / "temp_key"
    temp_signing_files.write_text(priv)

    local_config.jwt_signing.active_key_file = str(temp_signing_files)
    local_config.jwt_signing.key_files = [str(temp_signing_files)]

    set_config(local_config)
    app = setup_fastapi()

    app.dependency_overrides[get_auth_headers_service] = lambda: auth_headers_service
    app.dependency_overrides[get_irreversible_pseudonym_service] = lambda: (
        local_irreversible_pseudonym_service
    )
    app.dependency_overrides[get_reversible_pseudonym_service] = lambda: (
        local_reversible_pseudonym_service
    )
    app.dependency_overrides[get_hsm_key_version_service] = lambda: (
        hsm_key_version_service
    )
    app.dependency_overrides[get_organization_public_key_service] = lambda: (
        organization_public_key_service
    )
    app.dependency_overrides[get_oprf_service] = lambda: local_oprf_service
    app.dependency_overrides[get_saml_service_client] = lambda: saml_service_client
    app.dependency_overrides[get_jwt_signing_service] = lambda: jwt_signing_service
    app.dependency_overrides[get_jwe_token_service] = lambda: jwe_token_service

    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="session")
def valid_organization_id() -> Oin:
    return Oin("00000099000000002000")


@pytest.fixture(scope="session")
def valid_organization_id_2() -> Oin:
    return Oin("00000099000000003000")


@pytest.fixture(scope="session")
def valid_client_organization_id() -> Oin:
    return Oin("00000099000000001000")


@pytest.fixture(scope="session")
def valid_client_common_name() -> str:
    return "client_common_name"


@pytest.fixture(scope="session")
def mock_personal_id() -> PersonalId:
    return PersonalId("NL", "bsn", "999990007")


@pytest.fixture(scope="session")
def mock_personal_id_2() -> PersonalId:
    return PersonalId("NL", "bsn", "999990019")


ALL_SCOPES = " ".join(scope.value for scope in AuthorizationScope)


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
        "x-gf-scope": ALL_SCOPES,
    }


def personal_id_types(
    db_session: DbSession, names: list[PersonalIdType]
) -> list[PersonalIdTypeEntity]:
    stmt = select(PersonalIdTypeEntity).where(
        PersonalIdTypeEntity.name.in_([str(n) for n in names])
    )
    return list(db_session.execute(stmt).scalars().all())


@pytest.fixture
def persisted_organization_2(
    db_session: DbSession,
    valid_organization_id_2: Oin,
) -> OrganizationEntity:
    return create_organization(db_session, valid_organization_id_2)


@pytest.fixture
def persisted_organization(
    db_session: DbSession,
    valid_organization_id: Oin,
) -> OrganizationEntity:
    return create_organization(db_session, valid_organization_id)


@pytest.fixture
def org_without_key_versions(valid_organization_id_2: Oin) -> OrganizationEntity:
    return OrganizationEntity(
        external_id=valid_organization_id_2,
        name="test_org_no_versions",
    )


@pytest.fixture
def org_with_irreversible_pseudonym_type(
    valid_organization_id_2: Oin, db_session: DbSession
) -> OrganizationEntity:
    personal_ids = personal_id_types(
        db_session, [PersonalIdType.IRREVERSIBLE_PSEUDONYM]
    )
    new_org = OrganizationEntity(
        external_id=valid_organization_id_2,
        name="test org 2",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=list(personal_ids),
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))
        ],
    )
    db_session.add(new_org)
    db_session.commit()

    return new_org


@pytest.fixture
def org_with_reversible_pseudonym_type(
    valid_organization_id_2: Oin, db_session: DbSession
) -> OrganizationEntity:
    personal_ids = personal_id_types(db_session, [PersonalIdType.REVERSIBLE_PSEUDONYM])
    new_org = OrganizationEntity(
        external_id=valid_organization_id_2,
        name="test org 2",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=list(personal_ids),
    )
    db_session.add(new_org)
    db_session.commit()

    return new_org


@pytest.fixture
def org_with_personal_id_type(
    valid_organization_id_2: Oin, db_session: DbSession
) -> OrganizationEntity:
    personal_ids = personal_id_types(db_session, [PersonalIdType.PERSONAL_ID])
    new_org = OrganizationEntity(
        external_id=valid_organization_id_2,
        name="test org 2",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=list(personal_ids),
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))
        ],
    )
    db_session.add(new_org)
    db_session.commit()

    return new_org


def create_organization(
    db_session: DbSession,
    external_id: Oin,
) -> OrganizationEntity:
    org = (
        db_session.session.query(OrganizationEntity)
        .filter(OrganizationEntity.external_id == external_id.value)
        .first()
    )
    if org:
        return org
    personal_ids = personal_id_types(db_session, [PersonalIdType.OPRF])
    assert len(personal_ids) == 1
    org = OrganizationEntity(
        external_id=external_id,
        name="test_org",
        receive_personal_id_types=list(personal_ids),
        request_personal_id_types=list(personal_ids),
        hsm_key_versions=[
            HsmKeyVersionEntity(version=1, from_dt=datetime.now(UTC))
        ],
    )
    db_session.add(org)
    db_session.commit()
    return org


def generate_rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
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


def create_signed_jws(
    private_key_pem: str,
    oin: Oin,
    algorithm: str = "RS256",
) -> str:
    key = JWK.from_pem(private_key_pem.encode())
    claims = {
        "iat": int(datetime.now(UTC).timestamp()),
        "oin": oin.value,
    }
    header = {"alg": algorithm, "jwk": key.export_public(as_dict=True)}

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


@pytest.fixture
def headers_with_scopes(
    valid_headers: dict[str, str],
) -> Callable[..., dict[str, str]]:
    def _build(*scopes: AuthorizationScope) -> dict[str, str]:
        return {
            **valid_headers,
            "x-gf-scope": " ".join(scope.value for scope in scopes),
        }

    return _build


@pytest.fixture
def reset_version_cache() -> Generator[None, None, None]:
    import app.utils.version

    yield
    app.utils.version._version_cache = False


def decrypt_signed(
    token: str, priv_key_pem: str, signing: JwtSigningService
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Decrypts a nested JWT and verifies the inner signature as a receiver
    would. Returns the JWE header, the JWS header and the claims."""
    outer = jwe.JWE()
    outer.deserialize(token)
    outer.decrypt(JWK.from_pem(priv_key_pem.encode("ascii")))

    inner = jws.JWS()
    inner.deserialize(outer.payload.decode("ascii"))
    kid = inner.jose_header["kid"]
    public = next(k for k in signing.public_jwks() if k["kid"] == kid)
    inner.verify(JWK(**public), alg="PS256")

    claims: dict[str, Any] = json.loads(inner.payload)
    return dict(outer.jose_header), dict(inner.jose_header), claims
