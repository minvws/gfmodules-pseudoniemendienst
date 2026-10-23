import base64
import secrets

from pydantic import SecretStr

from app.config import (
    Config,
    ConfigApp,
    ConfigAuthorizationHeaders,
    ConfigDatabase,
    ConfigHsm,
    ConfigJwtSigning,
    ConfigLocalKeys,
    ConfigSamlService,
    ConfigUvicorn,
)


def genkey(len: int) -> str:
    key_bytes = secrets.token_bytes(len)
    return base64.urlsafe_b64encode(key_bytes).decode("ascii")


def get_test_config() -> Config:
    return Config(
        app=ConfigApp(),
        database=ConfigDatabase(
            dsn=SecretStr(
                "postgresql+psycopg://postgres:postgres@postgres:5432/postgres"
            ),
            retry_backoff=[],
        ),
        uvicorn=ConfigUvicorn(),
        authorization_headers=ConfigAuthorizationHeaders(
            expected_audiences=["prs.service"]
        ),
        hsm=ConfigHsm(url="http://example.org"),
        local_keys=ConfigLocalKeys(master_key=SecretStr(genkey(32))),
        saml_service=ConfigSamlService(url="http://example.com", timeout=1),
        jwt_signing=ConfigJwtSigning(
            enabled=False,
            issuer="",
            key_files=[],
            hsm_key_labels=[],
            active_key_file="",
            active_key_label="",
        ),
    )
