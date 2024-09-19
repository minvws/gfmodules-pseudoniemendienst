import base64

from redis import Redis

from app.services import jwe
from app.types import Rid


class RidCache:
    """
    Cache for RIDs to prevent double exchange
    """
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    def is_rid_cached(self, rid: Rid) -> bool:
        key = self._get_rid_key(rid)
        return self.redis.exists(key)

    def cache_rid(self, rid: Rid) -> None:
        key = self._get_rid_key(rid)
        self.redis.set(key, "1")

    def remove_rid_from_cache(self, rid: Rid) -> None:
        key = self._get_rid_key(rid)
        self.redis.delete(key)

    @staticmethod
    def _get_rid_key(rid: Rid):
        (_, _, _, _, tag) = jwe.split_jwe(str(rid))
        tag = base64.urlsafe_b64encode(tag)
        return "rid-tag-" + tag.decode('utf-8')