import http.server
import socketserver
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from app.services.http_client import retrying_session

_Responder = Callable[[int], tuple[int, bytes] | None]


class _Server(socketserver.TCPServer):
    allow_reuse_address = True


def _make_handler(
    responder: _Responder, attempts: list[int]
) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            attempts.append(1)
            result = responder(len(attempts))
            if result is None:
                # Drop the connection with no response, the way a transient
                # network failure looks to the client.
                self.close_connection = True
                return
            status, body = result
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    return Handler


@contextmanager
def _flaky_server(responder: _Responder) -> Iterator[tuple[str, list[int]]]:
    attempts: list[int] = []
    server = _Server(("127.0.0.1", 0), _make_handler(responder, attempts))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", attempts
    finally:
        server.shutdown()
        server.server_close()


def test_retrying_session_recovers_from_transient_connection_failures() -> None:
    def responder(attempt: int) -> tuple[int, bytes] | None:
        return None if attempt < 3 else (200, b'{"ok": true}')

    with _flaky_server(responder) as (url, attempts):
        response = retrying_session().post(url, timeout=5)

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert len(attempts) == 3


def test_retrying_session_does_not_retry_an_http_error_status() -> None:
    def responder(attempt: int) -> tuple[int, bytes] | None:
        return 500, b"{}"

    with _flaky_server(responder) as (url, attempts):
        response = retrying_session().post(url, timeout=5)

    assert response.status_code == 500
    assert len(attempts) == 1
