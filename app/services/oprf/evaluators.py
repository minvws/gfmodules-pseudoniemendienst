import logging
from dataclasses import dataclass
from typing import Protocol

import gfmodules.logging as gflog
import pyoprf

from app.config import ConfigOprf
from app.logging.events import SLEUTELTYPE_OPRF_SECRET, Log
from app.models.oin import Oin
from app.services.hsm.client import HsmClient
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
        return f"oin-{self.oin}-oprf-v{self.version}"


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
            if not self._client.label_exists(str(label)):
                self._generate_key(label)

            ret[version] = self._client.oprf_evaluate(str(label), blinded_bytes)

        return ret

    def _generate_key(self, label: OprfHsmKeyLabel) -> None:
        self._client.generate_oprf_key(str(label))
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
