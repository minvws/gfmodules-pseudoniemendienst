import json
from datetime import datetime, timezone
from typing import List

from app.config import ConfigRid
from app.services import jwe
from app.services.bpg_service import BpgService
from app.services.crypto.crypto_service import CryptoService
from app.services.jwe import ALGORITHMS, JWEVerifyException
from app.services.rid_cache import RidCache
from app.types import BasePseudonym, Rid

class RidException(Exception):
    """
    Base exception for RID service
    """
    pass

class EncryptionExhaustedException(RidException):
    """
    Exception raised when the key has been exhausted
    """
    pass

class NoExchangeAllowedException(RidException):
    """
    Exception raised when an exchange is not allowed
    """
    pass


class DecodeException(RidException):
    """
    Exception raised when decoding a RID fails
    """
    pass

class VerificationException(RidException):
    """
    Exception raised when verifying a RID fails
    """
    pass


class RidService:
    def __init__(self, config: ConfigRid, crypto_service: CryptoService, rid_cache: RidCache) -> None:
        self.crypto_service = crypto_service
        self.config = config
        self.rid_cache = rid_cache

        if self.config.alg == "AES-256-GCM":
            self.jwe_alg = ALGORITHMS.A256GCM
        else:
            raise ValueError("Unsupported algorithm")

        self.rid_env_key_id = self.config.key_name + "-" + str(self.config.key_version)
        self.rid_enc_remaining = int(self.config.max_encryptions)

    def is_healthy(self) -> bool:
        """
        Check if the service is healthy. This is when the key has not been exhausted
        """
        return self.rid_enc_remaining > int(self.config.key_renewal_at)

    def generate_iv(self) -> bytes:
        """
        Generate an IV for the encryption
        :return: IV bytes
        """
        self.rid_enc_remaining -= 1
        if self.rid_enc_remaining == 0:
            raise EncryptionExhaustedException("No more encryption attempts left for key")

        if self.rid_enc_remaining < int(self.config.key_renewal_at):
            print("Warning: key needs to be renewed")

        iv = self.config.iv_prefix.encode('utf-8') + self.rid_enc_remaining.to_bytes(8, byteorder='big')
        if len(iv) != 12:
            raise ValueError("IV length is not 12")

        return iv

    def extract_bp(self, rid: Rid) -> BasePseudonym|None:
        """
        Extract the BP from a RID
        """
        return self.get_subject_from_rid(rid)

    def exchange_bp(self, subject: BasePseudonym, issuer: str) -> Rid:
        """
        Generate a RID for a BP
        """
        if issuer not in ['PRS', 'VAD']:
            raise ValueError("Invalid issuer")

        now = datetime.now(tz=timezone.utc)
        claims = {
            "iss": issuer,
            "sub": str(subject),
            "iat": int(now.timestamp()),
        }
        payload = json.dumps(claims)

        rid_data = jwe.encrypt(
            crypto_service=self.crypto_service,
            key_id=self.rid_env_key_id,
            plaintext = payload.encode('utf-8'),
            iv=self.generate_iv(),
            encryption=self.jwe_alg,
            algorithm=ALGORITHMS.DIR,
        )
        rid = Rid(rid_data)

        # store RID into cache so we can exchange it later
        self.rid_cache.cache_rid(rid)

        return rid

    def exchange_rid(self, rid: Rid, count=1, issuer="PRS") -> List[Rid]:
        """
        Exchange a RID for one or more RIDs. This is done by extracting the BP from the RID and generating a new RIDs for it
        """
        bp = self.get_subject_from_rid(rid)
        if bp is None:
            raise ValueError("Invalid BP found in RID")

        return [self.exchange_bp(bp, issuer) for _ in range(count)]

    def is_valid(self, rid: Rid) -> bool:
        return self.get_subject_from_rid(rid) is not None


    def verify_and_decode_rid(self, rid: Rid) -> dict:
        """
        Decode a RID into its parts
        """
        try:
            plaintext = jwe.decrypt(self.crypto_service, str(rid))
            parts = json.loads(plaintext)

            if parts['iss'] != 'PRS' and parts['iss'] != 'VAD':
                raise DecodeException("Invalid issuer")
            if not parts['sub']:
                raise DecodeException("Missing subject")
            if not parts['iat']:
                raise DecodeException("Missing iat")

            if parts['iat'] > datetime.now(tz=timezone.utc).timestamp():
                raise DecodeException("Invalid iat")

            return parts
        except ValueError:
            raise DecodeException("Invalid JWE token")
        except JWEVerifyException as e:
            raise VerificationException("Invalid JWE token: {e}")


    def get_subject_from_rid(self, rid: Rid) -> BasePseudonym|None:
        """
        Check if a given RID is valid
        """
        try:
            parts = self.verify_and_decode_rid(rid)
        except VerificationException:
            return None
        except DecodeException:
            return None

        # Check if the BP found in the subject is valid and return if so
        bp = BasePseudonym(parts['sub'])
        if BpgService.is_valid(bp):
            return bp

        return None
