import logging
from typing import Any

import requests

from app.services.http_client import HttpService

logger = logging.getLogger(__name__)


class SamlServiceError(Exception):
    """Raised when the PRS-SAML service cannot be reached or returns an error."""

    def __init__(self, error_type: str, message: str):
        super().__init__(message)
        self.error_type = error_type


class SamlServiceClient:
    """HTTP client for the internal PRS-SAML service (the SAML-ontvanger),
    which processes DigiD SAML responses so XML parsing stays out of this
    process."""

    def __init__(
        self,
        url: str,
        timeout: float = 5.0,
        cert_file: str | None = None,
        key_file: str | None = None,
        ca_cert_file: str | None = None,
    ):
        self._http = HttpService(
            endpoint=url,
            timeout=timeout,
            mtls_cert=cert_file,
            mtls_key=key_file,
            verify_ca=ca_cert_file or True,
        )

    def decrypt(self, payload: Any) -> Any:
        try:
            response = self._http.do_request("POST", "/saml/decrypt", json=payload)
        except requests.exceptions.RequestException as e:
            logger.warning("PRS-SAML service unreachable: %s", e)
            raise SamlServiceError("saml_service_unreachable", str(e)) from e

        if response.status_code != 200:
            raise SamlServiceError(
                "saml_service_error",
                f"PRS-SAML service returned status {response.status_code}",
            )
        return response.json()
