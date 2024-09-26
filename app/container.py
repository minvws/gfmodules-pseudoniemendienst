import inject
import redis

from app.config import get_config
from app.services.bpg_service import BpgService
from app.services.crypto.crypto_service import CryptoService

from app.services.crypto.hsm_crypto_service import HsmCryptoService
from app.services.crypto.json_keystore import JsonKeyStorage
from app.services.crypto.memory_crypto_service import MemoryCryptoService
from app.services.iv_service import IvService
from app.services.pdn_service import PdnService
from app.services.rid_cache import RidCache
from app.services.rid_service import RidService


def container_config(binder: inject.Binder) -> None:
    config = get_config()

    crypto_service: CryptoService|None = None

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
    else:
        raise ValueError(f"Unknown keystore type {config.app.keystore}")


    iv_service = IvService(config.iv.path, config.iv.block_size)
    iv_service.set_iv_counter(config.iv.start, if_not_exists=True)
    binder.bind(IvService, iv_service)

    redis_service = redis.Redis(config.redis.host, config.redis.port, config.redis.db)
    binder.bind(redis.Redis, redis_service)

    rid_cache = RidCache(redis_service)
    binder.bind(RidCache, rid_cache)

    rid_service = RidService(config.rid, crypto_service, rid_cache, iv_service)
    binder.bind(RidService, rid_service)

    bpg_service = BpgService(config.bpg, crypto_service)
    binder.bind(BpgService, bpg_service)

    pdn_service = PdnService(config.bpg, crypto_service, redis_service)
    binder.bind(PdnService, pdn_service)


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


if not inject.is_configured():
    inject.configure(container_config)
