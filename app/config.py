from enum import Enum
import configparser
import os
from typing import Any

from pydantic import BaseModel, ValidationError, field_validator
from pydantic import Field

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
    mtls_override_cert: str | None = Field(default=None)
    enable_test_routes: bool = Field(default=False)

class ConfigDatabase(BaseModel):
    dsn: str
    create_tables: bool = Field(default=False)
    retry_backoff: list[float] = Field(
        default=[0.1, 0.2, 0.4, 0.8, 1.6, 3.2, 4.8, 6.4, 10.0]
    )
    pool_size: int = Field(default=5, ge=0, lt=100)
    max_overflow: int = Field(default=10, ge=0, lt=100)
    pool_pre_ping: bool = Field(default=False)
    pool_recycle: int = Field(default=3600, ge=0)

    @field_validator("create_tables", mode="before")
    def validate_create_tables(cls, v: Any) -> bool:
        if v in (None, "", " "):
            return False
        if isinstance(v, str):
            return v.lower() in ("yes", "true", "t", "1")
        return bool(v)

    @field_validator("pool_size", mode="before")
    def validate_pool_size(cls, v: Any) -> int:
        if v in (None, "", " "):
            return 5
        return int(v)

    @field_validator("max_overflow", mode="before")
    def validate_max_overflow(cls, v: Any) -> int:
        if v in (None, "", " "):
            return 10
        return int(v)

    @field_validator("pool_recycle", mode="before")
    def validate_pool_recycle(cls, v: Any) -> int:
        if v in (None, "", " "):
            return 3600
        return int(v)

class ConfigUvicorn(BaseModel):
    swagger_enabled: bool = Field(default=False)
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


class ConfigOprf(BaseModel):
    server_key_file: str = Field(default="")


class ConfigPseudonym(BaseModel):
    hmac_key: str | None = Field(default=None)
    aes_key: str | None = Field(default=None)
    rid_aes_key: str | None = Field(default=None)


class Config(BaseModel):
    app: ConfigApp
    database: ConfigDatabase
    uvicorn: ConfigUvicorn
    oprf: ConfigOprf
    pseudonym: ConfigPseudonym


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


def reset_config() -> None:
    global _CONFIG
    _CONFIG = None


def set_config(config: Config) -> None:
    global _CONFIG
    _CONFIG = config


def get_config(path: str | None = None) -> Config:
    global _CONFIG
    global _PATH

    if _CONFIG is not None:
        return _CONFIG

    if path is None:
        path = os.environ.get(_ENVIRONMENT_CONFIG_PATH_NAME) or _PATH

    # To be inline with other python code, we use INI-type files for configuration. Since this isn't
    # a standard format for pydantic, we need to do some manual parsing first.
    ini_data = read_ini_file(path)

    try:
        # Convert database.retry_backoff to a list of floats
        if "retry_backoff" in ini_data["database"] and isinstance(
            ini_data["database"]["retry_backoff"], str
        ):
            # convert the string to a list of floats
            ini_data["database"]["retry_backoff"] = [
                float(i) for i in ini_data["database"]["retry_backoff"].split(",")
            ]

        _CONFIG = Config.model_validate(ini_data)
    except ValidationError as e:
        raise e

    return _CONFIG
