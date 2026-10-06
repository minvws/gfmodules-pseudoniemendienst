from dataclasses import dataclass

from app.config import Config
from app.services.hsm.client import HsmClient
from app.services.hsm_key_version_service import HsmKeyVersionService
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


@dataclass(frozen=True)
class KeyOperations:
    oprf_evaluator: OprfEvaluator
    reversible_keys: ReversibleKeyOperations
    irreversible_keys: IrreversibleKeyOperations


def build_key_operations(
    config: Config, hsm_key_version_service: HsmKeyVersionService
) -> KeyOperations:
    """
    OPRF, reversible and irreversible pseudonyms always share one backend:
    either all three delegate to the HSM API, or all three fall back to local
    (dev/test) key derivation. hsm.hsm_url decides which, for all three at once.
    """
    if config.hsm.hsm_url:
        hsm_client = HsmClient(config.hsm)
        return KeyOperations(
            oprf_evaluator=HsmOprfEvaluator(config.hsm, hsm_key_version_service),
            reversible_keys=HsmReversibleKeyOperations(hsm_client),
            irreversible_keys=HsmIrreversibleKeyOperations(hsm_client),
        )

    # Only the local fallback needs a master key; real HSM mode derives and
    # holds its own per-organization/version keys internally.
    master_key = config.pseudonym.load_master_key()
    return KeyOperations(
        oprf_evaluator=LocalOprfEvaluator(config.oprf.load_server_key()),
        reversible_keys=LocalReversibleKeyOperations(master_key),
        irreversible_keys=LocalIrreversibleKeyOperations(master_key),
    )
