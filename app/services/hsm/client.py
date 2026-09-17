import base64
import logging
from typing import Any

import gfmodules.logging as gflog
import requests
from gfmodules.logging import correlation_headers

from app.config import ConfigOprf
from app.logging.events import Log

logger = logging.getLogger(__name__)

# PRS-SYS-006: HSM unreachable
HSM_UNREACHABLE_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
)


class HsmKeyNotFound(Exception):
    """The HSM holds no key with the requested label."""


class HsmKeyExists(Exception):
    """A key with the requested label already exists in the HSM."""


def _expected_error(response: requests.Response) -> Exception | None:
    """
    The HSM API answers every HSMError with a 422 and only distinguishes them
    by text. Two of them are expected in normal operation: a missing key on
    first use and a duplicate create when two instances race on that first use.
    """
    if response.status_code != 422:
        return None
    try:
        description = response.json().get("error_description", "")
    except Exception:  # noqa: BLE001 - a body that is not JSON is just not one of ours
        return None
    if not isinstance(description, str):
        return None
    if description == "Object already exists":
        return HsmKeyExists(description)
    if description.startswith("No such key") or description.endswith("not found"):
        return HsmKeyNotFound(description)
    return None


class HsmClient:
    """Client for nl-rdo-hsm-api-service. Keys are addressed by label."""

    def __init__(self, config: ConfigOprf, timeout: float = 10.0) -> None:
        self._config = config
        self._timeout = timeout

    def post(self, path: str, payload: dict[str, Any], operation: str) -> Any:
        """
        POST to the HSM API. ``operation`` names the HSM operation in the
        PRS-KEY-007 event when the HSM refuses it.
        """
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
            gflog.emit(
                logger,
                Log.SYS_HSM_UNREACHABLE,
                "HSM/KMS unreachable",
                fields={"error_reason": str(e)},
            )
            raise
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            expected = _expected_error(response)
            if expected is not None:
                raise expected from e
            # PRS-KEY-007: the HSM was reachable but refused the operation.
            gflog.emit(
                logger,
                Log.HSM_OPERATION_FAILED,
                "HSM operation failed",
                fields={
                    "operation_type": operation,
                    "error_reason": f"http_{response.status_code}",
                },
                exc_info=e,
            )
            raise
        return response.json()

    def _generate(self, path: str, payload: dict[str, Any], label: str) -> bool:
        """Create the key. Returns False when it already existed, which happens
        when another instance created it first; that is not an error."""
        try:
            data = self.post(path, payload, "keygen")
        except HsmKeyExists:
            logger.info("HSM key %r already exists", label)
            return False
        if "result" not in data:
            gflog.emit(
                logger,
                Log.HSM_OPERATION_FAILED,
                "HSM operation failed",
                fields={
                    "operation_type": "keygen",
                    "error_reason": "no_result_in_response",
                },
            )
            raise ValueError(f"could not generate key {label!r} in HSM")
        return True

    def label_exists(self, label: str, objtype: str = "SECRET_KEY") -> bool:
        data = self.post("", {"label": label, "objtype": objtype}, "lookup")
        return len(data["objects"] or []) > 0

    def generate_oprf_key(self, label: str) -> bool:
        return self._generate("/generate/oprf", {"label": label}, label)

    def generate_aes_key(self, label: str) -> bool:
        return self._generate("/generate/aes", {"label": label}, label)

    def generate_secret_key(self, label: str, bits: int = 256) -> bool:
        return self._generate("/generate/secret", {"label": label, "bits": bits}, label)

    def destroy(self, label: str) -> None:
        self.post("/destroy", {"label": label}, "destroy")

    def oprf_evaluate(self, label: str, blinded: bytes) -> bytes:
        data = self.post(
            "/oprf/evaluate",
            {"label": label, "blinded_point": base64.b64encode(blinded).decode()},
            "oprf_evaluate",
        )
        return base64.b64decode(data["result"])

    def hmac(self, label: str, data: bytes, mechanism: str = "SHA256_HMAC") -> bytes:
        result = self.post(
            "/sign",
            {
                "label": label,
                "objtype": "SECRET_KEY",
                "data": base64.b64encode(data).decode(),
                "mechanism": mechanism,
            },
            "hmac",
        )
        return base64.b64decode(result["result"]["data"])

    def encrypt(self, label: str, iv: bytes, data: bytes) -> bytes:
        """AES-CBC with PKCS#7 padding, the HSM API default."""
        result = self.post(
            "/encrypt",
            {
                "label": label,
                "objtype": "SECRET_KEY",
                "data": base64.b64encode(data).decode(),
                "iv": base64.b64encode(iv).decode(),
                "mechanism": "AES_CBC_PAD",
            },
            "encrypt",
        )
        return base64.b64decode(result["result"]["data"])

    def decrypt(self, label: str, iv: bytes, data: bytes) -> bytes:
        result = self.post(
            "/decrypt",
            {
                "label": label,
                "objtype": "SECRET_KEY",
                "data": base64.b64encode(data).decode(),
                "iv": base64.b64encode(iv).decode(),
            },
            "decrypt",
        )
        return base64.b64decode(result["result"]["data"])
