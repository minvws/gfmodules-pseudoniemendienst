import base64
import logging
from dataclasses import dataclass
from typing import Any, Protocol

import pyoprf
import requests

from app.config import ConfigOprf
from app.logging.context import correlation_headers
from app.logging.events import SYS_HSM_UNREACHABLE, log_event
from app.models.oin import Oin
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
        self._hsm_config = hsm_config
        self._hsm_key_version_service = hsm_key_version_service

    def evaluate(
        self,
        recipient_org_oin: Oin,
        blinded_bytes: bytes,
    ) -> dict[int, bytes]:
        active_versions = self._hsm_key_version_service.get_active_or_create_version_numbers_by_organization_oin(
            recipient_org_oin
        )

        ret: dict[int, bytes] = {}
        for version in active_versions:
            label = HsmKeyLabel(recipient_org_oin, version)
            if not self._label_exists(label):
                self._generate_key(label)

            ret[version] = self._evaluate_label(label, blinded_bytes)

        return ret

    def _hsm_post(self, path: str, payload: dict[str, str]) -> Any:
        cfg = self._hsm_config
        url = f"{cfg.hsm_url}/hsm/{cfg.hsm_module}/{cfg.hsm_slot}{path}"
        try:
            response = requests.post(
                url,
                json=payload,
                headers=correlation_headers(),
                timeout=10,
                verify=cfg.hsm_ca_cert_file or True,
                cert=(
                    (cfg.hsm_cert_file, cfg.hsm_key_file)
                    if (cfg.hsm_cert_file and cfg.hsm_key_file)
                    else None
                ),
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            log_event(
                logger,
                SYS_HSM_UNREACHABLE,
                "HSM/KMS unreachable",
                error_reason=str(e),
            )
            raise
        response.raise_for_status()
        return response.json()

    def _generate_key(self, label: HsmKeyLabel) -> None:
        data = self._hsm_post("/generate/oprf", {"label": str(label)})
        if "result" not in data:
            raise ValueError("could not generate the OPRF secret in HSM")

    def _label_exists(self, label: HsmKeyLabel) -> bool:
        data = self._hsm_post("", {"label": str(label), "objtype": "SECRET_KEY"})
        result = data["objects"] or []
        return len(result) > 0

    def _evaluate_label(self, label: HsmKeyLabel, blinded_bytes: bytes) -> bytes:
        data = self._hsm_post(
            "/oprf/evaluate",
            {
                "label": str(label),
                "blinded_point": base64.b64encode(blinded_bytes).decode(),
            },
        )
        return base64.b64decode(data["result"])
