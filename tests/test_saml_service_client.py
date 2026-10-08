from unittest.mock import MagicMock

import pytest
import requests

from app.services.http_client import HttpService
from app.services.saml.client import SamlServiceClient, SamlServiceError


def _client(http: MagicMock) -> SamlServiceClient:
    return SamlServiceClient(http)


def _http(status_code: int = 200, body: object = None) -> MagicMock:
    http = MagicMock(spec=HttpService)
    http.do_request.return_value.status_code = status_code
    http.do_request.return_value.json.return_value = body
    return http


def test_client_posts_the_payload_to_saml_decrypt() -> None:
    http = _http(body={"ok": True})

    assert _client(http).decrypt({"foo": "bar"}) == {"ok": True}
    http.do_request.assert_called_once_with(
        "POST", "/saml/decrypt", json={"foo": "bar"}
    )


def test_client_raises_on_non_200() -> None:
    with pytest.raises(SamlServiceError) as exc_info:
        _client(_http(status_code=500)).decrypt({})
    assert exc_info.value.error_type == "saml_service_error"


def test_client_raises_on_connection_error() -> None:
    http = _http()
    http.do_request.side_effect = requests.exceptions.ConnectionError("refused")

    with pytest.raises(SamlServiceError) as exc_info:
        _client(http).decrypt({})
    assert exc_info.value.error_type == "saml_service_unreachable"
