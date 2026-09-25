import logging
from dataclasses import dataclass
from typing import Protocol

import gfmodules.logging as gflog
import pyoprf

from app.config import ConfigOprf
from app.logging.events import SLEUTELTYPE_OPRF_SECRET, Log
from app.models.oin import Oin
from app.services.hsm.client import HsmClient, HsmKeyNotFound
from app.services.hsm_key_version_service import HsmKeyVersionService

logger = logging.getLogger(__name__)


class OprfEvaluator(Protocol):
    def evaluate(
        self, recipient_org_oin: Oin, blinded_bytes: bytes
    ) -> dict[int, bytes]: ...


@dataclass(frozen=True)
class OprfHsmKeyLabel:
    oin: Oin
    version: int

    def __str__(self) -> str:
        # Always the bare 20-character OIN, also for a RecipientOrganizationOin
        # whose str() carries the "oin:" prefix. The evaluator gets the
        # recipient from the request while the cleanup derives the same label
        # from the stored organization; both must name the same HSM object.
        return f"oin-{self.oin.value}-oprf-v{self.version}"


class LocalOprfEvaluator:
    def __init__(self, server_key: bytes):
        self._server_key = server_key

    def evaluate(
        self, recipient_org_oin: Oin, blinded_bytes: bytes
    ) -> dict[int, bytes]:
        return {1: pyoprf.evaluate(self._server_key, blinded_bytes)}


class HsmOprfEvaluator:
    def __init__(
        self,
        hsm_config: ConfigOprf,
        hsm_key_version_service: HsmKeyVersionService,
    ):
        self._client = HsmClient(hsm_config)
        self._hsm_key_version_service = hsm_key_version_service

    def evaluate(
        self,
        recipient_org_oin: Oin,
        blinded_bytes: bytes,
    ) -> dict[int, bytes]:
        active_versions = self._hsm_key_version_service.get_active_version_numbers_by_organization_oin(
            recipient_org_oin
        )

        ret: dict[int, bytes] = {}
        for version in active_versions:
            label = OprfHsmKeyLabel(recipient_org_oin, version)
            try:
                ret[version] = self._client.oprf_evaluate(str(label), blinded_bytes)
            except HsmKeyNotFound:
                # First use of this key version: create the secret and retry.
                self._generate_key(label)
                ret[version] = self._client.oprf_evaluate(str(label), blinded_bytes)

        return ret

    def _generate_key(self, label: OprfHsmKeyLabel) -> None:
        if not self._client.generate_oprf_key(str(label)):
            # Another instance won the race; its key is the one we use.
            return
        # PRS-KEY-001: OPRF secrets are generated lazily on first use.
        gflog.emit(
            logger,
            Log.KEY_GENERATED,
            "OPRF secret generated in HSM",
            fields={
                "sleuteltype": SLEUTELTYPE_OPRF_SECRET,
                "organisatie_oin": label.oin.value,
                "secret_id": str(label),
                "sleutel_versie": label.version,
            },
        )
