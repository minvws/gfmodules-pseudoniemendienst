import base64
import logging

import inject

from app.config import get_config
from app.db.db import Database
from app.services.auth.header import AuthHeaderService
from app.services.mtls_service import MtlsService

from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.key_resolver import KeyResolver
from app.services.oprf.oprf_service import OprfService
from app.services.org_service import OrgService
from app.services.pseudonym_service import PseudonymService
from app.services.rid_service import RidService

logger = logging.getLogger(__name__)

# Minimum master key size in bytes. The master key must have at least as much
# entropy as the 256-bit keys HKDF derives from it.
_MIN_MASTER_KEY_BYTES = 32


def _load_master_key(raw: str) -> bytes:
    """
    Decode and validate the configured pseudonym master key.

    All pseudonym, reversible-pseudonym and RID keys are derived from this key,
    so an empty or weak master key would make every pseudonym forgeable and every
    reversible pseudonym/RID decryptable. Refuse to start rather than silently
    run with a b"" key.
    """
    if not raw:
        raise ValueError(
            "pseudonym.master_key is not configured. Set a base64-encoded key of "
            "at least 32 bytes, e.g. `openssl rand -base64 32`."
        )

    key = base64.urlsafe_b64decode(raw)
    if len(key) < _MIN_MASTER_KEY_BYTES:
        raise ValueError(
            f"pseudonym.master_key is too short ({len(key)} bytes decoded); "
            f"at least {_MIN_MASTER_KEY_BYTES} bytes are required."
        )

    return key


def container_config(binder: inject.Binder) -> None:
    config = get_config()

    db = Database(
        dsn=config.database.dsn,
        pool_size=config.database.pool_size,
        max_overflow=config.database.max_overflow,
        pool_pre_ping=config.database.pool_pre_ping,
        pool_recycle=config.database.pool_recycle,
    )
    binder.bind(Database, db)

    key_resolver = KeyResolver(db)
    binder.bind(KeyResolver, key_resolver)

    org_service = OrgService(db)
    binder.bind(OrgService, org_service)

    mtls_service = MtlsService(config.development.override_mtls_cert)
    binder.bind(MtlsService, mtls_service)

    hsm_key_version_service = HsmKeyVersionService(db)
    binder.bind(HsmKeyVersionService, hsm_key_version_service)

    hsm_key_cleanup_service = HsmKeyCleanupService(config.oprf, hsm_key_version_service)
    binder.bind(HsmKeyCleanupService, hsm_key_cleanup_service)

    auth_header_service = AuthHeaderService(
        expected_audiences=config.authorization_headers.expected_audiences
    )
    binder.bind(AuthHeaderService, auth_header_service)

    if config.oprf.hsm_url:
        oprf_service = OprfService(
            server_key=None,
            hsm_config=config.oprf,
            hsm_key_version_service=hsm_key_version_service,
        )
    else:
        try:
            with open(config.oprf.server_key_file, "r") as f:
                key = f.read().strip()
            if key == "":
                raise ValueError(
                    "OPRF server key file is empty. Generate it using the 'make generate-oprf-key' command."
                )
        except FileNotFoundError:
            raise FileNotFoundError(
                "OPRF server key file not found. Generate it using the 'make generate-oprf-key' command."
            )
        oprf_service = OprfService(server_key=key)
    binder.bind(OprfService, oprf_service)

    # This should be done through an HSM
    master_key = _load_master_key(config.pseudonym.master_key)

    pseudonym_service = PseudonymService(master_key)
    binder.bind(PseudonymService, pseudonym_service)

    rid_service = RidService(master_key, b"RID:v1")
    binder.bind(RidService, rid_service)


def get_mtls_service() -> MtlsService:
    return inject.instance(MtlsService)


def get_org_service() -> OrgService:
    return inject.instance(OrgService)


def get_rid_service() -> RidService:
    return inject.instance(RidService)


def get_pseudonym_service() -> PseudonymService:
    return inject.instance(PseudonymService)


def get_key_resolver() -> KeyResolver:
    return inject.instance(KeyResolver)


def get_oprf_service() -> OprfService:
    return inject.instance(OprfService)


def get_database() -> Database:
    return inject.instance(Database)


def get_hsm_key_version_service() -> HsmKeyVersionService:
    return inject.instance(HsmKeyVersionService)


def get_hsm_key_cleanup_service() -> HsmKeyCleanupService:
    return inject.instance(HsmKeyCleanupService)


def get_auth_headers_service() -> AuthHeaderService:
    return inject.instance(AuthHeaderService)


if not inject.is_configured():
    inject.configure(container_config)
