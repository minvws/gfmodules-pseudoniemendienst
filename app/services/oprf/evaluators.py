import logging
from dataclasses import dataclass
from typing import Protocol

import pyoprf

from app.config import ConfigOprf
from app.models.oin import Oin
from app.services.hsm.client import HsmClient
from app.services.hsm_key_version_service import HsmKeyVersionService

logger = logging.getLogger(__name__)


class OprfEvaluator(Protocol):
    def evaluate(
        self, recipient_org_oin: Oin, blinded_bytes: bytes
    ) -> dict[int, bytes]: ...


@dataclass(frozen=True)
class HsmKeyLabel:
    oin: Oin
    version: int

    def __str__(self) -> str:
        return f"oin-{self.oin}-v{self.version}"


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
            label = str(HsmKeyLabel(recipient_org_oin, version))
            if not self._client.label_exists(label):
                self._client.generate_oprf_key(label)

            ret[version] = self._client.oprf_evaluate(label, blinded_bytes)

        return ret
