import configparser
import os
from collections.abc import Callable
from enum import Enum
from typing import Any

from gfmodules.logging import ConfigLogging as GFConfigLogging
from gfmodules.logging.ini import split_comma_separated
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

_PATH = "app.conf"
_ENVIRONMENT_CONFIG_PATH_NAME = "FASTAPI_CONFIG_PATH"
_CONFIG = None


class LogLevel(str, Enum):
    debug = "debug"
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class ConfigApp(BaseModel):
    loglevel: LogLevel = Field(default=LogLevel.info)
    enable_test_routes: bool = Field(default=False)
    enable_exchange_services_routes: bool = Field(default=True)
    enable_saml_exchange_routes: bool = Field(default=False)
    enable_jwt_signing: bool = Field(default=False)


def _int_or_default(default: int) -> Callable[[Any, Any], int]:
    def validate(cls: Any, v: Any) -> int:
        if v in (None, "", " "):
            return default
        return int(v)

    return validate


class ConfigDatabase(BaseModel):
    # SecretStr so the DSN password never appears in reprs or logs
    dsn: SecretStr
    retry_backoff: list[float] = Field(
        default=[0.1, 0.2, 0.4, 0.8, 1.6, 3.2, 4.8, 6.4, 10.0]
    )
    pool_size: int = Field(default=5, ge=0, lt=100)
    max_overflow: int = Field(default=10, ge=0, lt=100)
    pool_pre_ping: bool = Field(default=False)
    pool_recycle: int = Field(default=3600, ge=0)

    _split_retry_backoff = field_validator("retry_backoff", mode="before")(
        split_comma_separated(float)
    )

    _validate_pool_size = field_validator("pool_size", mode="before")(
        _int_or_default(5)
    )
    _validate_max_overflow = field_validator("max_overflow", mode="before")(
        _int_or_default(10)
    )
    _validate_pool_recycle = field_validator("pool_recycle", mode="before")(
        _int_or_default(3600)
    )


class ConfigUvicorn(BaseModel):
    swagger_enabled: bool = Field(default=False)
    document_gf_headers: bool = Field(default=False)
    docs_url: str = Field(default="/docs")
    redoc_url: str = Field(default="/redoc")
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8502, gt=0, lt=65535)
    reload: bool = Field(default=True)
    reload_delay: float = Field(default=1)
    reload_dirs: list[str] = Field(default=["app"])
    use_ssl: bool = Field(default=False)
    ssl_base_dir: str | None = Field(default=None)
    ssl_cert_file: str | None = Field(default=None)
    ssl_key_file: str | None = Field(default=None)
    root_path: str = Field(default="")


class ConfigHsm(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str | None = Field(default=None)
    module: str = Field(default="softhsm")
    slot: str = Field(default="SoftHSMLabel")
    timeout: float = Field(default=10.0, gt=0)
    cert_file: str | None = Field(default=None)
    key_file: str | None = Field(default=None)
    ca_cert_file: str | None = Field(default=None)


class ConfigLocalKeys(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # SecretStr so the key material never appears in reprs or logs
    master_key: SecretStr = Field(default=SecretStr(""))
    oprf_server_key_file: str | None = Field(default=None)


class ConfigSamlService(BaseModel):
    # Base URL of the internal PRS-SAML service (the SAML-ontvanger). Required
    # when enable_saml_exchange_routes is set.
    url: str | None = Field(default=None)
    timeout: float = Field(default=5.0, gt=0)
    # mTLS towards the PRS-SAML service.
    # Leave unset for plain HTTP in local development.
    cert_file: str | None = Field(default=None)
    key_file: str | None = Field(default=None)
    ca_cert_file: str | None = Field(default=None)


class ConfigJwtSigning(BaseModel):
    # The `iss` claim in signed pseudonym JWTs. Receivers map it to the PRS
    # JWKS URL in their own configuration. Required when enable_jwt_signing is set.
    issuer: str = Field(default="")
    # PEM files with the RSA private keys for signing pseudonym JWTs. All of
    # them are published for verification; only active_key_file signs.
    # Required when enable_jwt_signing is set.
    key_files: list[str] = Field(default=[])
    active_key_file: str = Field(default="")

    _split_key_files = field_validator("key_files", mode="before")(
        split_comma_separated()
    )


class ConfigAuthorizationHeaders(BaseModel):
    expected_audiences: list[str]

    @field_validator("expected_audiences", mode="before")
    @classmethod
    def validate_aud(cls, data: Any) -> list[str]:
        if isinstance(data, str):
            return data.split()

        if isinstance(data, list):
            return data

        raise ValueError("Invalid input on `expected_audience`, please check config")


class ConfigLogging(GFConfigLogging):
    _split_console_streams = field_validator("console_streams", mode="before")(
        split_comma_separated()
    )


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app: ConfigApp
    logging: ConfigLogging = Field(default_factory=ConfigLogging)
    database: ConfigDatabase
    uvicorn: ConfigUvicorn
    hsm: ConfigHsm = Field(default_factory=ConfigHsm)
    local_keys: ConfigLocalKeys = Field(default_factory=ConfigLocalKeys)
    authorization_headers: ConfigAuthorizationHeaders
    saml_service: ConfigSamlService = Field(default_factory=ConfigSamlService)
    jwt_signing: ConfigJwtSigning = Field(default_factory=ConfigJwtSigning)


def read_ini_file(path: str) -> Any:
    ini_data = configparser.ConfigParser()
    ini_data.read(path)

    ret = {}
    for section in ini_data.sections():
        ret[section] = dict(ini_data[section])
        remove_empty_values(ret[section])
    return ret


def remove_empty_values(section: dict[str, Any]) -> None:
    for key in list(section.keys()):
        if section[key] == "":
            del section[key]


def set_config(config: Config) -> None:
    global _CONFIG
    _CONFIG = config


def get_config(path: str | None = None) -> Config:
    global _CONFIG

    if _CONFIG is not None:
        return _CONFIG

    if path is None:
        path = os.environ.get(_ENVIRONMENT_CONFIG_PATH_NAME) or _PATH

    # To be inline with other python code, we use INI-type files for configuration. Since this isn't
    # a standard format for pydantic, we need to do some manual parsing first.
    ini_data = read_ini_file(path)

    _CONFIG = Config.model_validate(ini_data)

    return _CONFIG
