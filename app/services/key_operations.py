import base64
import logging
from dataclasses import dataclass

from app.config import Config, ConfigOprf
from app.services.hsm.client import HsmClient
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.http_client import HttpService
from app.services.irreversible.keys import (
    HsmIrreversibleKeyOperations,
    IrreversibleKeyOperations,
    LocalIrreversibleKeyOperations,
)
from app.services.oprf.evaluators import (
    HsmOprfEvaluator,
    LocalOprfEvaluator,
    OprfEvaluator,
)
from app.services.reversible.keys import (
    HsmReversibleKeyOperations,
    LocalReversibleKeyOperations,
    ReversibleKeyOperations,
)

logger = logging.getLogger(__name__)

_MIN_MASTER_KEY_BYTES = 32


def _load_master_key(raw: str) -> bytes:
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


def _load_server_key(path: str) -> bytes:
    try:
        with open(path, "r") as f:
            key = f.read().strip()
        if key == "":
            raise ValueError(
                "OPRF server key file is empty. Generate it using the 'make generate-oprf-key' command."
            )
    except FileNotFoundError:
        raise FileNotFoundError(
            "OPRF server key file not found. Generate it using the 'make generate-oprf-key' command."
        )
    return base64.urlsafe_b64decode(key)


@dataclass(frozen=True)
class KeyOperations:
    oprf_evaluator: OprfEvaluator
    reversible_keys: ReversibleKeyOperations
    irreversible_keys: IrreversibleKeyOperations

    @classmethod
    def from_config(
        cls, config: Config, version_service: HsmKeyVersionService
    ) -> "KeyOperations":
        if config.oprf.hsm_url:
            return cls._hsm(config.oprf, version_service)
        return cls._local(config)

    @classmethod
    def _hsm(
        cls, config: ConfigOprf, version_service: HsmKeyVersionService
    ) -> "KeyOperations":
        hsm_client = HsmClient(
            HttpService(
                endpoint=f"{config.hsm_url}/hsm/{config.hsm_module}/{config.hsm_slot}",
                timeout=10.0,
                mtls_cert=config.hsm_cert_file,
                mtls_key=config.hsm_key_file,
                verify_ca=config.hsm_ca_cert_file or True,
            )
        )
        return cls(
            oprf_evaluator=HsmOprfEvaluator(hsm_client, version_service),
            reversible_keys=HsmReversibleKeyOperations(hsm_client),
            irreversible_keys=HsmIrreversibleKeyOperations(hsm_client),
        )

    @classmethod
    def _local(cls, config: Config) -> "KeyOperations":
        logger.info("HSM not configured, using keys derived from the master key")
        master_key = _load_master_key(config.pseudonym.master_key.get_secret_value())
        return cls(
            oprf_evaluator=LocalOprfEvaluator(
                _load_server_key(config.oprf.server_key_file)
            ),
            reversible_keys=LocalReversibleKeyOperations(master_key),
            irreversible_keys=LocalIrreversibleKeyOperations(master_key),
        )
