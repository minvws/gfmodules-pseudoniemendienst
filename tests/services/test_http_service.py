from unittest.mock import MagicMock, patch

import pytest
from requests import ConnectionError, Response, Timeout

from app.services.http_service import HttpService


@patch("app.services.http_service.Session")
def test_do_request_should_succeed(
    mock_session_class: MagicMock, http_service: HttpService
) -> None:
    http_service._session = mock_session_class.return_value

    mock_response = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_session_class.return_value.request.return_value = mock_response

    result = http_service.do_request(
        method="POST",
        path="/test",
        json={"key": "value"},
        params={"param": "value"},
        headers={"x-custom": "header"},
    )

    assert result == mock_response
    mock_session_class.return_value.request.assert_called_once()
    call_args = mock_session_class.return_value.request.call_args
    assert call_args[0][0] == "POST"
    assert call_args[0][1] == "example.org/test"
    assert call_args[1]["json"] == {"key": "value"}
    assert call_args[1]["params"] == {"param": "value"}
    assert call_args[1]["headers"] is not None


@patch("app.services.http_service.Session")
def test_do_request_should_handle_timeout(
    mock_session_class: MagicMock, http_service: HttpService
) -> None:
    http_service._session = mock_session_class.return_value
    mock_session_class.return_value.request.side_effect = Timeout()
    with pytest.raises(Timeout):
        http_service.do_request(method="GET", path="/test")


@patch("app.services.http_service.Session")
def test_do_request_should_handle_connection_error(
    mock_session_class: MagicMock, http_service: HttpService
) -> None:
    http_service._session = mock_session_class.return_value
    mock_session_class.return_value.request.side_effect = ConnectionError()
    with pytest.raises(ConnectionError):
        http_service.do_request(method="GET", path="/test")


@patch("app.services.http_service.Session")
def test_do_request_should_handle_http_error(
    mock_session_class: MagicMock, http_service: HttpService
) -> None:
    http_service._session = mock_session_class.return_value
    mock_response = MagicMock(spec=Response)
    mock_response.status_code = 404
    mock_session_class.return_value.request.return_value = mock_response

    result = http_service.do_request(method="GET", path="/test")

    assert result == mock_response
    assert result.status_code == 404
