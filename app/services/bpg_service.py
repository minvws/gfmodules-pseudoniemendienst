import base64

from app.config import ConfigBpg
from app.services.crypto.crypto_service import CryptoService, CryptoAlgorithm
from app.types import BasePseudonym


class BpgService:
    """
    Service for handling the Base Pseudonym Generation (BPG) process
    """
    def __init__(self, config: ConfigBpg, crypto_service: CryptoService) -> None:
        self.crypto_service = crypto_service
        self.config = config

        self.bpg_env_key_id = self.config.key_name + "-" + str(self.config.key_version)

        try:
            key = f"bp-gen-key-{self.config.key_name.lower()}-{str(self.config.key_version)}-alg"
            self.bpg_env_key_alg = self.config.model_dump()[key]
        except KeyError:
            self.bpg_env_key_alg = self.config.default_alg

        if self.bpg_env_key_alg == "HS256":
            self.hash_alg = CryptoAlgorithm.SHA256
        else:
            raise ValueError(f"Unsupported algorithm {self.bpg_env_key_alg}")


    def exchange(self, bsn: str) -> BasePseudonym:
        """
        Generate a Base Pseudonym from a BSN
        """
        bpg_key_version = self.config.key_version

        bpg_hmac = self.crypto_service.sign(self.hash_alg, bsn.encode(), self.bpg_env_key_id)
        return BasePseudonym(f"{bpg_key_version}:{str(base64.b64encode(bpg_hmac), 'ascii')}")


    @staticmethod
    def is_valid(bp: BasePseudonym) -> bool:
        try:
            parts = str(bp).split(":")
            if len(parts) != 2:
                return False
        except ValueError:
            return False

        return True