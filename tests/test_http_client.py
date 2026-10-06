from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest
from gfmodules.logging import CORRELATION_ID_HEADER, bind_context
from requests.exceptions import ConnectionError, Timeout

from app.services.http_client import HttpService


@pytest.fixture
def http_service() -> HttpService:
    return HttpService(
        endpoint="https://example/api/",
        timeout=5,
        mtls_cert="path/to/cert",
        mtls_key="path/to/key",
        verify_ca="path/to/ca",
    )


@pytest.fixture
def session_request() -> Iterator[MagicMock]:
    with patch("requests.Session.request") as request:
        yield request


@pytest.mark.parametrize(
    ("path", "url"), [("", "https://example/api"), ("/r/1", "https://example/api/r/1")]
)
def test_do_request_sends_the_request(
    session_request: MagicMock, http_service: HttpService, path: str, url: str
) -> None:
    response = http_service.do_request("POST", path, json={"a": 1}, params={"q": "x"})

    assert response is session_request.return_value
    assert session_request.call_args.args == ("POST", url)
    assert session_request.call_args.kwargs == {
        "json": {"a": 1},
        "params": {"q": "x"},
        "headers": {},
        "timeout": 5,
        "cert": ("path/to/cert", "path/to/key"),
        "verify": "path/to/ca",
    }


@pytest.mark.parametrize("error", [Timeout, ConnectionError])
def test_do_request_propagates_transport_errors(
    session_request: MagicMock, http_service: HttpService, error: type[Exception]
) -> None:
    session_request.side_effect = error
    with pytest.raises(error):
        http_service.do_request("GET")


@pytest.mark.parametrize(("cert", "key"), [(None, None), ("c", None), (None, "k")])
def test_do_request_sends_no_client_cert_without_both_cert_and_key(
    session_request: MagicMock, cert: str | None, key: str | None
) -> None:
    HttpService("https://example", 5, mtls_cert=cert, mtls_key=key).do_request("GET")

    assert session_request.call_args.kwargs["cert"] is None
    assert session_request.call_args.kwargs["verify"] is True


def test_do_request_adds_the_correlation_id_without_mutating_caller_headers(
    session_request: MagicMock, http_service: HttpService
) -> None:
    headers = {"Authorization": "Bearer x"}
    with bind_context({"correlation_id": "some-generated-id"}):
        http_service.do_request("GET", headers=headers)

    assert session_request.call_args.kwargs["headers"] == {
        "Authorization": "Bearer x",
        CORRELATION_ID_HEADER: "some-generated-id",
    }
    assert headers == {"Authorization": "Bearer x"}


def test_http_service_reuses_a_pooled_session(http_service: HttpService) -> None:
    adapter = http_service._session.get_adapter("https://example")

    assert adapter is http_service._session.get_adapter("http://example")
    assert adapter._pool_maxsize == 40  # type: ignore[attr-defined]
