import base64

import inject

from app.config import get_config
from app.db.db import Database
from app.services.mtls_service import MtlsService

from app.services.key_resolver import KeyResolver
from app.services.oprf.oprf_service import OprfService
from app.services.org_service import OrgService
from app.services.pseudonym_service import PseudonymService
from app.services.rid_service import RidService
import logging

logger = logging.getLogger(__name__)

def container_config(binder: inject.Binder) -> None:
    config = get_config()

    db = Database(dsn=config.database.dsn)
    binder.bind(Database, db)

    key_resolver = KeyResolver(db)
    binder.bind(KeyResolver, key_resolver)

    org_service = OrgService(db)
    binder.bind(OrgService, org_service)

    mtls_service = MtlsService(config.app.mtls_override_cert, org_service)
    binder.bind(MtlsService, mtls_service)

    try:
        with open(config.oprf.server_key_file, "r") as f:
            key = f.read().strip()
        if key == "":
            raise ValueError("OPRF server key file is empty. Generate it using the 'make generate-oprf-key' command.")
    except FileNotFoundError:
        raise FileNotFoundError("OPRF server key file not found. Generate it using the 'make generate-oprf-key' command.")
    oprf_service = OprfService(key)
    binder.bind(OprfService, oprf_service)

    pseudonym_service = PseudonymService(
        base64.urlsafe_b64decode(config.pseudonym.hmac_key or ""),
        base64.urlsafe_b64decode(config.pseudonym.aes_key or ""),
    )
    binder.bind(PseudonymService, pseudonym_service)

    rid_service = RidService(
        base64.urlsafe_b64decode(config.pseudonym.rid_aes_key or ""),
    )
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

if not inject.is_configured():
    inject.configure(container_config)
