from unittest.mock import MagicMock

import pytest
import requests.exceptions

from app.services.http_service import HttpService
from app.services.saml.client import SamlServiceClient, SamlServiceError


def test_decrypt_should_return_json_when_success(
    saml_service_client: SamlServiceClient,
) -> None:
    # Mock the HTTP service to return a successful response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"decrypted": "data"}

    # Replace the client's HTTP service with a mock
    saml_service_client._http = MagicMock(spec=HttpService)
    saml_service_client._http.do_request.return_value = mock_response

    payload = {"encrypted": "saml_data"}

    result = saml_service_client.decrypt(payload)

    assert result == {"decrypted": "data"}
    saml_service_client._http.do_request.assert_called_once_with(
        "POST", "/saml/decrypt", json=payload
    )


def test_decrypt_should_raise_saml_service_error_when_non_200(
    saml_service_client: SamlServiceClient,
) -> None:
    # Mock the HTTP service to return a non-200 response
    mock_response = MagicMock()
    mock_response.status_code = 500

    saml_service_client._http = MagicMock(spec=HttpService)
    saml_service_client._http.do_request.return_value = mock_response

    payload = {"encrypted": "saml_data"}

    with pytest.raises(SamlServiceError) as exc_info:
        saml_service_client.decrypt(payload)

    assert exc_info.value.error_type == "saml_service_error"
    assert "PRS-SAML service returned status 500" in str(exc_info.value)


def test_decrypt_should_raise_saml_service_unreachable_when_connection_fails(
    saml_service_client: SamlServiceClient,
) -> None:
    # Mock the HTTP service to raise a connection error
    saml_service_client._http = MagicMock(spec=HttpService)
    saml_service_client._http.do_request.side_effect = (
        requests.exceptions.ConnectionError("refused")
    )

    payload = {"encrypted": "saml_data"}

    with pytest.raises(SamlServiceError) as exc_info:
        saml_service_client.decrypt(payload)

    assert exc_info.value.error_type == "saml_service_unreachable"
