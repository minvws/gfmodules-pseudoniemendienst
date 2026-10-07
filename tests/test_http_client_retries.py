import http.server
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import DEFAULT, patch

import pytest
import requests
from urllib3.util import connection

from app.services.http_client import HttpService


@contextmanager
def _server(status: int | None) -> Iterator[tuple[HttpService, list[str]]]:
    attempts: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            attempts.append(self.path)
            if status is None:
                self.close_connection = True
                return
            self.send_response(status)
            self.send_header("Retry-After", "0")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield HttpService(f"http://127.0.0.1:{server.server_port}", 5), attempts
    finally:
        server.shutdown()
        server.server_close()


def test_retries_until_the_service_accepts_connections() -> None:
    refused_twice = [ConnectionRefusedError, ConnectionRefusedError, DEFAULT]
    with (
        _server(200) as (http, attempts),
        patch.object(
            connection,
            "create_connection",
            wraps=connection.create_connection,
            side_effect=refused_twice,
        ) as create_connection,
    ):
        response = http.do_request("POST")

    assert response.status_code == 200
    assert create_connection.call_count == 3
    assert len(attempts) == 1


def test_does_not_retry_a_connection_dropped_after_the_request_was_sent() -> None:
    with (
        _server(None) as (http, attempts),
        pytest.raises(requests.exceptions.ConnectionError),
    ):
        http.do_request("POST")

    assert len(attempts) == 1


@pytest.mark.parametrize("status", [429, 500, 503])
def test_does_not_retry_an_http_error_status(status: int) -> None:
    with _server(status) as (http, attempts):
        response = http.do_request("POST")

    assert response.status_code == status
    assert len(attempts) == 1
