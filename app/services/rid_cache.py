import base64

from redis import Redis

from app.services import jwe
from app.prs_types import Rid


class RidCache:
    """
    Cache for RIDs to prevent double exchange
    """
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    def is_rid_cached(self, rid: Rid) -> bool:
        key = self._get_rid_key(rid)
        return self.redis.exists(key) # type: ignore

    def cache_rid(self, rid: Rid) -> None:
        key = self._get_rid_key(rid)
        self.redis.set(key, "1")

    def remove_rid_from_cache(self, rid: Rid) -> None:
        key = self._get_rid_key(rid)
        self.redis.delete(key)

    @staticmethod
    def _get_rid_key(rid: Rid) -> str:
        (_, _, _, _, tag) = jwe.split_jwe(str(rid))
        str_tag = base64.urlsafe_b64encode(tag).decode('utf-8')

        return "rid-tag-" + str_tag
