import base64

import redis


from app.config import ConfigBpg
from app.services.crypto.crypto_service import CryptoService, CryptoAlgorithms
from app.prs_types import BasePseudonym, OrganisationId, PDN

SALT = b"iRealisatie"       # Fixed salt?

class PdnService:
    def __init__(self, config: ConfigBpg, crypto_service: CryptoService, redis: redis.Redis) -> None:
        self.crypto_service = crypto_service
        self.config = config
        self.redis = redis

        self.bpg_env_key_id = self.config.key_name + "-" + str(self.config.key_version)

        self.key_len = 32
        self.hmac_algo = CryptoAlgorithms.SHA256

    def exchange(self, bp: BasePseudonym, org_id: OrganisationId) -> PDN:
        """
        Exchanges a Base Pseudonym for a PDN Pseudonym for the given organisation
        """
        org_key_version = self.get_organisation_version(org_id)

        key_label = f"{str(org_id)}:{org_key_version}"
        self.crypto_service.generate_key(key_label)

        hmac = self.crypto_service.sign(self.hmac_algo, bp.as_bytes(), key_label)
        hmac_b64 = base64.b64encode(hmac).decode('utf-8')

        return PDN(f"{str(self.config.key_version)}.{str(org_key_version)}.{hmac_b64}")

    def get_organisation_version(self, org_id: OrganisationId) -> str:
        """
        Get the version of the organisation key
        """
        p_gen_key_version = f"p-gen-key-{str(org_id)}"
        org_key_version = "1"

        res: bytes = self.redis.get(p_gen_key_version) # type: ignore
        if res is None:
            self.redis.set(p_gen_key_version, org_key_version)
        else:
            org_key_version = res.decode('utf-8')

        return org_key_version

