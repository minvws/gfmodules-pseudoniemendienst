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
    keystore: str = Field(default="json")

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

class ConfigAuth(BaseModel):
    override_cert: str | None = Field(default=None)
    allowed_curves: str = Field(default="")
    min_rsa_bitsize: int = Field(default=2048)
    allow_cert_list: str = Field(default="auth_cert.json")

class ConfigRid(BaseModel):
    key_name : str= Field(default="REK")
    key_version : int = Field(default=1)
    alg : str = Field(default="AES-256-GCM")
    key_renewal_at : int = Field(default=1000)
    iv_prefix : str = Field(default="RIVF")
    max_age_for_pdn_exchange_via_vad : int = Field(default=10)
    max_age_for_pdn_exchange_via_healthcare_provider : int = Field(default=3600)


class ConfigBpg(BaseModel):
    key_name : str = Field(default="BPGK")
    key_version : int = Field(default=1)
    default_alg : str = Field(default="HS256")

    class Config:
        extra = "allow"

class ConfigIv(BaseModel):
    path: str = Field(default="iv.json")
    block_size: int = Field(default=100)
    start: int = Field(default=9223372036854775807) # 2^63 - 1

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


class ConfigRedis(BaseModel):
    host: str = Field(default="localhost")
    port: int = Field(default=6379, gt=0, lt=65535)
    db: int = Field(default=0, ge=0)
    cert_path: str | None = Field(default=None)
    key_path: str | None = Field(default=None)
    ca_path: str | None = Field(default=None)

class ConfigJsonKeystore(BaseModel):
    path: str = Field(default="keystore.json")


class ConfigHsmApiKeystore(BaseModel):
    url: str
    module: str
    slot: str
    cert_path: str

class ConfigHsmKeystore(BaseModel):
    slot: int = Field(default=0)
    slot_pin: str = Field(default="1234")
    library: str = Field(default="/usr/local/lib/softhsm/libsofthsm2.so")

class ConfigOprf(BaseModel):
    server_key: str = Field(default="")

class Config(BaseModel):
    app: ConfigApp
    database: ConfigDatabase
    auth: ConfigAuth
    uvicorn: ConfigUvicorn
    rid: ConfigRid
    bpg: ConfigBpg
    redis: ConfigRedis
    iv: ConfigIv
    json_keystore: ConfigJsonKeystore
    hsm_keystore: ConfigHsmKeystore
    hsm_api_keystore: ConfigHsmApiKeystore
    oprf: ConfigOprf


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
        path = _PATH

    path = path or os.environ.get(_ENVIRONMENT_CONFIG_PATH_NAME) or _PATH

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
