from pydantic import SecretStr

from app.config import (
    Config,
    ConfigApp,
    ConfigAuthorizationHeaders,
    ConfigDatabase,
    ConfigHsm,
    ConfigUvicorn,
)


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
        hsm=ConfigHsm(url="example.org"),
    )
