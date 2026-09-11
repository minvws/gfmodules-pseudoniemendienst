import base64
import logging
from typing import Any

import requests

from app.config import ConfigOprf
from app.logging.context import correlation_headers
from app.logging.events import SYS_HSM_UNREACHABLE, log_event

logger = logging.getLogger(__name__)

# PRS-SYS-006: HSM unreachable
HSM_UNREACHABLE_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
)


class HsmClient:
    """Client for nl-rdo-hsm-api-service. Keys are addressed by label."""

    def __init__(self, config: ConfigOprf, timeout: float = 10.0) -> None:
        self._config = config
        self._timeout = timeout

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        cfg = self._config
        url = f"{cfg.hsm_url}/hsm/{cfg.hsm_module}/{cfg.hsm_slot}{path}"
        try:
            response = requests.post(
                url,
                json=payload,
                headers=correlation_headers(),
                timeout=self._timeout,
                verify=cfg.hsm_ca_cert_file or True,
                cert=(
                    (cfg.hsm_cert_file, cfg.hsm_key_file)
                    if (cfg.hsm_cert_file and cfg.hsm_key_file)
                    else None
                ),
            )
        except HSM_UNREACHABLE_ERRORS as e:
            log_event(
                logger,
                SYS_HSM_UNREACHABLE,
                "HSM/KMS unreachable",
                error_reason=str(e),
            )
            raise
        response.raise_for_status()
        return response.json()

    def label_exists(self, label: str, objtype: str = "SECRET_KEY") -> bool:
        data = self.post("", {"label": label, "objtype": objtype})
        return len(data["objects"] or []) > 0

    def generate_oprf_key(self, label: str) -> None:
        data = self.post("/generate/oprf", {"label": label})
        if "result" not in data:
            raise ValueError(f"could not generate OPRF secret {label!r} in HSM")

    def generate_aes_key(self, label: str) -> None:
        data = self.post("/generate/aes", {"label": label})
        if "result" not in data:
            raise ValueError(f"could not generate AES key {label!r} in HSM")

    def generate_secret_key(self, label: str, bits: int = 256) -> None:
        data = self.post("/generate/secret", {"label": label, "bits": bits})
        if "result" not in data:
            raise ValueError(f"could not generate secret key {label!r} in HSM")

    def destroy(self, label: str) -> None:
        self.post("/destroy", {"label": label})

    def oprf_evaluate(self, label: str, blinded: bytes) -> bytes:
        data = self.post(
            "/oprf/evaluate",
            {"label": label, "blinded_point": base64.b64encode(blinded).decode()},
        )
        return base64.b64decode(data["result"])

    def hmac(self, label: str, data: bytes, mechanism: str = "SHA256_HMAC") -> bytes:
        result = self.post(
            "/sign",
            {
                "label": label,
                "data": base64.b64encode(data).decode(),
                "mechanism": mechanism,
            },
        )
        return base64.b64decode(result["result"]["data"])

    def encrypt(self, label: str, iv: bytes, data: bytes) -> bytes:
        """AES-CBC with PKCS#7 padding, the HSM API default."""
        result = self.post(
            "/encrypt",
            {
                "label": label,
                "data": base64.b64encode(data).decode(),
                "iv": base64.b64encode(iv).decode(),
            },
        )
        return base64.b64decode(result["result"]["data"])

    def decrypt(self, label: str, iv: bytes, data: bytes) -> bytes:
        result = self.post(
            "/decrypt",
            {
                "label": label,
                "data": base64.b64encode(data).decode(),
                "iv": base64.b64encode(iv).decode(),
            },
        )
        return base64.b64decode(result["result"]["data"])
