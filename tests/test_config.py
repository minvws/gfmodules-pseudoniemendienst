import base64
import os
import secrets

from app.config import (
    Config,
    ConfigApp,
    ConfigDatabase,
    ConfigUvicorn,
    LogLevel,
    ConfigAuth,
    ConfigRid,
    ConfigBpg,
    ConfigRedis,
    ConfigIv,
    ConfigJsonKeystore,
    ConfigHsmKeystore,
    ConfigHsmApiKeystore,
    ConfigOprf,
    ConfigPseudonym,
)


def genkey(len: int) -> str:
    key_bytes = secrets.token_bytes(len)
    return base64.urlsafe_b64encode(key_bytes).decode('ascii')


def get_test_config() -> Config:

    # Write OPRF key for testing if not exists
    if not os.path.exists("secrets/test-oprf.key"):
        os.makedirs("secrets", exist_ok=True)
        with open("secrets/test-oprf.key", "w") as f:
            f.write(genkey(32))


    return Config(
        app=ConfigApp(
            loglevel=LogLevel.error,
            keystore="json",
            mtls_override_cert="./secrets/uzi.crt"
        ),
        database=ConfigDatabase(
            dsn="postgresql+psycopg://postgres:postgres@localhost/testing",
            create_tables=False,
            retry_backoff=[0.1, 0.2, 0.4, 0.8, 1.6, 3.2, 4.8, 6.4, 10.0],
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=False,
            pool_recycle=1,
        ),
        uvicorn=ConfigUvicorn(
            swagger_enabled=False,
            docs_url="/docs",
            redoc_url="/redoc",
            host="0.0.0.0",
            port=8503,
            reload=True,
            use_ssl=False,
            ssl_base_dir=None,
            ssl_cert_file=None,
            ssl_key_file=None,
        ),
        auth=ConfigAuth(
            override_cert = None,
            allowed_curves= "",
            min_rsa_bitsize = 2048,
            allow_cert_list = "auth_cert.json.example",
        ),
        rid=ConfigRid(
            key_name = "REK",
            key_version = 1,
            alg = "AES-256-GCM",
            key_renewal_at=1000,
            iv_prefix = "IV",
            max_age_for_pdn_exchange_via_vad=10,
            max_age_for_pdn_exchange_via_healthcare_provider=3600,
        ),
        bpg=ConfigBpg(
            key_name = "BGPK",
            key_version=1,
            default_alg="HS256",
        ),
        iv=ConfigIv(
            path="secrets/iv.json",
            block_size=100,
            start=9223372036854775807, # 2^63 - 1
        ),
        redis=ConfigRedis(
            host="localhost",
            port=6379,
            db=0,
            cert_path=None,
            key_path=None,
            ca_path=None,
        ),
        json_keystore=ConfigJsonKeystore(
            path="secrets/keystore.json",
        ),
        hsm_keystore=ConfigHsmKeystore(
            slot=1,
            slot_pin="your_hsm_pin",
            library="/path/to/your/pkcs11/library.so",
        ),
        hsm_api_keystore=ConfigHsmApiKeystore(
            url="https://your-hsm-api-endpoint",
            module="your_module_name",
            slot="your_slot_identifier",
            cert_path="",
        ),
        oprf=ConfigOprf(
            server_key_file="secrets/test-oprf.key",
        ),
        pseudonym=ConfigPseudonym(
            hmac_key=genkey(32),
            aes_key=genkey(32),
            rid_aes_key=genkey(32),
        )
    )

