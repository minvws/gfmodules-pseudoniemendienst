import inject
import redis

from app.config import get_config
from app.db.db import Database
from app.services.auth_cert_service import AuthCertService
from app.services.bpg_service import BpgService
from app.services.crypto.crypto_service import CryptoService
from app.services.crypto.hsm_api_crypto_service import HsmApiCryptoService

from app.services.crypto.hsm_crypto_service import HsmCryptoService
from app.services.crypto.json_keystore import JsonKeyStorage
from app.services.crypto.memory_crypto_service import MemoryCryptoService
from app.services.iv_service import IvService
from app.services.key_resolver import KeyResolver
from app.services.oprf.oprf_service import OprfService
from app.services.pdn_service import PdnService
from app.services.pseudonym_service import PseudonymService
from app.services.rid_cache import RidCache
from app.services.rid_service import RidService
from app.services.tls_service import TLSService


def container_config(binder: inject.Binder) -> None:
    config = get_config()

    db = Database(dsn=config.database.dsn)
    binder.bind(Database, db)

    tls_service = TLSService(config.auth.allowed_curves, config.auth.min_rsa_bitsize)
    auth_cert_service = AuthCertService(config.auth.allow_cert_list, tls_service)
    binder.bind(AuthCertService, auth_cert_service)

    crypto_service: CryptoService | None = None

    if config.app.keystore == "json":
        store = JsonKeyStorage(config.json_keystore.path)
        if not store.has_key('BPGK-1'):
            store.generate_key('BPGK-1')
        if not store.has_key('REK-1'):
            store.generate_key('REK-1')

        crypto_service = MemoryCryptoService(store)
        binder.bind(CryptoService, crypto_service)
    elif config.app.keystore == "hsm":
        crypto_service = HsmCryptoService(config.hsm_keystore.library, config.hsm_keystore.slot, config.hsm_keystore.slot_pin)
        binder.bind(CryptoService, crypto_service)
    elif config.app.keystore == "hsm_api":
        crypto_service = HsmApiCryptoService(config.hsm_api_keystore.url, config.hsm_api_keystore.module, config.hsm_api_keystore.slot, config.hsm_api_keystore.cert_path)
        binder.bind(CryptoService, crypto_service)
    else:
        raise ValueError(f"Unknown keystore type {config.app.keystore}")


    iv_service = IvService(config.iv.path, config.iv.block_size)
    iv_service.set_iv_counter(config.iv.start, if_not_exists=True)
    binder.bind(IvService, iv_service)

    if config.redis.cert_path is None or config.redis.cert_path == "":
        redis_service = redis.Redis(config.redis.host, config.redis.port, config.redis.db)
    else:
        redis_service = redis.Redis(config.redis.host, config.redis.port, config.redis.db, ssl=True, ssl_cert_reqs='required', ssl_ca_certs=config.redis.ca_path, ssl_certfile=config.redis.cert_path, ssl_keyfile=config.redis.key_path)

    binder.bind(redis.Redis, redis_service)

    rid_cache = RidCache(redis_service)
    binder.bind(RidCache, rid_cache)

    rid_service = RidService(config.rid, crypto_service, rid_cache, iv_service)
    binder.bind(RidService, rid_service)

    bpg_service = BpgService(config.bpg, crypto_service)
    binder.bind(BpgService, bpg_service)

    pdn_service = PdnService(config.bpg, crypto_service, redis_service)
    binder.bind(PdnService, pdn_service)

    key_resolver = KeyResolver(db)
    binder.bind(KeyResolver, key_resolver)

    with open(config.oprf.server_key_file, "r") as f:
        key = f.read().strip()
    if key == "":
        raise ValueError("OPRF server key file is empty. Generate it using the 'make generate-oprf-key' command.")
    oprf_service = OprfService(key)
    binder.bind(OprfService, oprf_service)

    pseudonym_service = PseudonymService(config.pseudonym.hmac_key.encode("utf-8"))
    binder.bind(PseudonymService, pseudonym_service)


def get_pseudonym_service() -> PseudonymService:
    return inject.instance(PseudonymService)

def get_key_resolver() -> KeyResolver:
    return inject.instance(KeyResolver)

def get_oprf_service() -> OprfService:
    return inject.instance(OprfService)

def get_rid_service() -> RidService:
    return inject.instance(RidService)


def get_bpg_service() -> BpgService:
    return inject.instance(BpgService)


def get_pdn_service() -> PdnService:
    return inject.instance(PdnService)

def get_redis() -> redis.Redis:
    return inject.instance(redis.Redis)

def get_rid_cache() -> RidCache:
    return inject.instance(RidCache)

def get_crypto_service() -> CryptoService:
    return inject.instance(CryptoService)

def get_authorization_service() -> AuthCertService:
    return inject.instance(AuthCertService)

def get_database() -> Database:
    return inject.instance(Database)

if not inject.is_configured():
    inject.configure(container_config)
