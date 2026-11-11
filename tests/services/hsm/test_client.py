import base64
from unittest.mock import MagicMock, patch

import pytest
from requests import Response
from requests.exceptions import ConnectionError, HTTPError, Timeout

from app.services.hsm.client import HsmClient, HsmKeyExists, HsmKeyNotFound


@patch("app.services.hsm.client.HttpService")
def test_post_should_succeed(mock_http_class: MagicMock, hsm_client: HsmClient) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "success"}
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client.post("/test", {"key": "value"}, "test_operation")

    assert result == {"result": "success"}
    mock_http_class.return_value.do_request.assert_called_once_with(
        "POST", "/test", json={"key": "value"}
    )


@patch("app.services.hsm.client.HttpService")
@pytest.mark.parametrize("exception", [ConnectionError(), Timeout()])
def test_post_should_raise_when_hsm_unreachable(
    mock_http_class: MagicMock, hsm_client: HsmClient, exception: Exception
) -> None:
    hsm_client._http = mock_http_class.return_value
    mock_http_class.return_value.do_request.side_effect = exception

    with pytest.raises(type(exception)):
        hsm_client.post("/test", {}, "test_operation")


@patch("app.services.hsm.client.HttpService")
def test_post_should_raise_http_error(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = HTTPError("500 Server Error")
    mock_http_class.return_value.do_request.return_value = mock_response

    with pytest.raises(HTTPError):
        hsm_client.post("/test", {}, "test_operation")


@patch("app.services.hsm.client.HttpService")
def test_generate_should_succeed(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "key_created"}
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client._generate("/generate/oprf", {"label": "test"}, "test_label")

    assert result is True


@patch("app.services.hsm.client.HttpService")
def test_generate_should_return_false_when_key_exists(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_http_class.return_value.do_request.side_effect = HsmKeyExists(
        "Object already exists"
    )

    result = hsm_client._generate("/generate/oprf", {"label": "test"}, "test_label")

    assert result is False


@patch("app.services.hsm.client.HttpService")
def test_generate_should_raise_when_no_result_in_response(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {}
    mock_http_class.return_value.do_request.return_value = mock_response

    with pytest.raises(ValueError, match="could not generate key"):
        hsm_client._generate("/generate/oprf", {"label": "test"}, "test_label")


@patch("app.services.hsm.client.HttpService")
def test_generate_should_raise_when_post_fails(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_http_class.return_value.do_request.side_effect = HsmKeyNotFound("No such key")

    with pytest.raises(HsmKeyNotFound):
        hsm_client._generate("/generate/oprf", {"label": "test"}, "test_label")


@patch("app.services.hsm.client.HttpService")
def test_label_exists_should_return_true_when_label_exists(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"objects": ["label1", "label2"]}
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client.label_exists("test_label")

    assert result is True


@patch("app.services.hsm.client.HttpService")
def test_label_exists_should_return_false_when_label_not_exists(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"objects": []}
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client.label_exists("test_label")

    assert result is False


@patch("app.services.hsm.client.HttpService")
def test_label_exists_should_return_false_when_objects_missing(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {}
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client.label_exists("test_label")

    assert result is False


@patch("app.services.hsm.client.HttpService")
def test_label_exists_should_raise_when_post_fails(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_http_class.return_value.do_request.side_effect = HsmKeyNotFound("No such key")

    with pytest.raises(HsmKeyNotFound):
        hsm_client.label_exists("test_label")


@patch("app.services.hsm.client.HttpService")
def test_destroy_if_present_should_return_true_when_label_exists(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response_exists: MagicMock = MagicMock(spec=Response)
    mock_response_exists.status_code = 200
    mock_response_exists.json.return_value = {"objects": ["test_label"]}

    mock_response_destroy: MagicMock = MagicMock(spec=Response)
    mock_response_destroy.status_code = 200
    mock_response_destroy.json.return_value = {}

    mock_http_class.return_value.do_request.side_effect = [
        mock_response_exists,
        mock_response_destroy,
    ]

    result = hsm_client.destroy_if_present("test_label")

    assert result is True
    assert mock_http_class.return_value.do_request.call_count == 2


@patch("app.services.hsm.client.HttpService")
def test_destroy_if_present_should_return_false_when_label_not_exists(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"objects": []}
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client.destroy_if_present("test_label")

    assert result is False
    assert mock_http_class.return_value.do_request.call_count == 1


@patch("app.services.hsm.client.HttpService")
def test_destroy_if_present_should_raise_when_destroy_fails(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_response_exists: MagicMock = MagicMock(spec=Response)
    mock_response_exists.status_code = 200
    mock_response_exists.json.return_value = {"objects": ["test_label"]}

    mock_http_class.return_value.do_request.side_effect = [
        mock_response_exists,
        HsmKeyNotFound("No such key"),
    ]

    with pytest.raises(HsmKeyNotFound):
        hsm_client.destroy_if_present("test_label")


@patch("app.services.hsm.client.HttpService")
def test_oprf_evaluate_should_succeed(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    blinded_input = b"test_blinded"
    expected_output = b"evaluated"

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "result": base64.b64encode(expected_output).decode()
    }
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client.oprf_evaluate("test_label", blinded_input)

    assert result == expected_output


@patch("app.services.hsm.client.HttpService")
def test_oprf_evaluate_should_raise_when_post_fails(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_http_class.return_value.do_request.side_effect = HsmKeyNotFound("No such key")

    with pytest.raises(HsmKeyNotFound):
        hsm_client.oprf_evaluate("test_label", b"test_blinded")


@patch("app.services.hsm.client.HttpService")
def test_hmac_should_succeed(mock_http_class: MagicMock, hsm_client: HsmClient) -> None:
    hsm_client._http = mock_http_class.return_value

    input_data = b"test_data"
    expected_output = b"signed"

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "result": {"data": base64.b64encode(expected_output).decode()}
    }
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client.hmac("test_label", input_data, "SHA256_HMAC")

    assert result == expected_output


@patch("app.services.hsm.client.HttpService")
def test_hmac_should_raise_when_post_fails(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_http_class.return_value.do_request.side_effect = HsmKeyNotFound("No such key")

    with pytest.raises(HsmKeyNotFound):
        hsm_client.hmac("test_label", b"test_data", "SHA256_HMAC")


@patch("app.services.hsm.client.HttpService")
def test_encrypt_should_succeed(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    input_data = b"test_data"
    iv = b"test_iv"
    expected_output = b"encrypted"

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "result": {"data": base64.b64encode(expected_output).decode()}
    }
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client.encrypt("test_label", iv, input_data)

    assert result == expected_output


@patch("app.services.hsm.client.HttpService")
def test_encrypt_should_raise_when_post_fails(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_http_class.return_value.do_request.side_effect = HsmKeyNotFound("No such key")

    with pytest.raises(HsmKeyNotFound):
        hsm_client.encrypt("test_label", b"test_iv", b"test_data")


@patch("app.services.hsm.client.HttpService")
def test_decrypt_should_succeed(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    input_data = b"test_data"
    iv = b"test_iv"
    expected_output = b"decrypted"

    mock_response: MagicMock = MagicMock(spec=Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "result": {"data": base64.b64encode(expected_output).decode()}
    }
    mock_http_class.return_value.do_request.return_value = mock_response

    result = hsm_client.decrypt("test_label", iv, input_data)

    assert result == expected_output


@patch("app.services.hsm.client.HttpService")
def test_decrypt_should_raise_when_post_fails(
    mock_http_class: MagicMock, hsm_client: HsmClient
) -> None:
    hsm_client._http = mock_http_class.return_value

    mock_http_class.return_value.do_request.side_effect = HsmKeyNotFound("No such key")

    with pytest.raises(HsmKeyNotFound):
        hsm_client.decrypt("test_label", b"test_iv", b"test_data")
