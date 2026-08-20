import io
import json
import logging
from typing import Any, Iterator

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.logging.context import (
    CLIENT_TRACE_ID_HEADER,
    CORRELATION_ID_HEADER,
    REQUEST_ID_HEADER,
    UNSET,
    correlation_headers,
    correlation_id_var,
    endpoint_var,
    method_var,
    request_id_var,
)
from app.logging.events import SYS_APP_STARTED, log_event
from app.logging.filters import AppFilter, LoggingStreams
from app.logging.formatter import JsonFormatter
from app.logging.middleware import RequestContextMiddleware, bind_request_context

CORRELATION_ID = "some-generated-id"


def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    with bind_request_context(request) as context:
        response = JSONResponse(
            status_code=500,
            content={
                "correlation_id": correlation_id_var.get(),
                "request_id": request_id_var.get(),
            },
        )
        if context is not None:
            context.apply_to(response)
        return response


@pytest.fixture
def middleware_client() -> Iterator[TestClient]:
    app = FastAPI()

    @app.get("/echo")
    def echo() -> dict[str, Any]:
        return {
            "correlation_id": correlation_id_var.get(),
            "endpoint": endpoint_var.get(),
            "method": method_var.get(),
            "outgoing": correlation_headers(),
        }

    @app.get("/boom")
    def boom() -> dict[str, Any]:
        raise RuntimeError("kaboom")

    app.add_middleware(RequestContextMiddleware)
    app.add_exception_handler(Exception, _unhandled_exception_handler)

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_inbound_correlation_id_reaches_the_endpoint(
    middleware_client: TestClient,
) -> None:
    response = middleware_client.get(
        "/echo", headers={CORRELATION_ID_HEADER: CORRELATION_ID}
    )

    assert response.json()["correlation_id"] == CORRELATION_ID


def test_correlation_id_is_echoed_on_the_response(
    middleware_client: TestClient,
) -> None:
    response = middleware_client.get(
        "/echo", headers={CORRELATION_ID_HEADER: CORRELATION_ID}
    )

    assert response.headers[CORRELATION_ID_HEADER] == CORRELATION_ID
    assert response.headers[REQUEST_ID_HEADER]


def test_missing_correlation_id_is_not_invented_or_echoed(
    middleware_client: TestClient,
) -> None:
    response = middleware_client.get("/echo")

    assert response.json()["correlation_id"] == UNSET
    assert CORRELATION_ID_HEADER not in response.headers


def test_correlation_id_header_lookup_is_case_insensitive(
    middleware_client: TestClient,
) -> None:
    response = middleware_client.get(
        "/echo", headers={"x-gf-correlation-id": CORRELATION_ID}
    )

    assert response.json()["correlation_id"] == CORRELATION_ID


def test_unsafe_characters_are_stripped(middleware_client: TestClient) -> None:
    response = middleware_client.get(
        "/echo", headers={CORRELATION_ID_HEADER: "abc$%^123"}
    )

    assert response.json()["correlation_id"] == "abc123"


def test_correlation_id_is_truncated(middleware_client: TestClient) -> None:
    response = middleware_client.get(
        "/echo", headers={CORRELATION_ID_HEADER: "a" * 200}
    )

    assert response.json()["correlation_id"] == "a" * 64


def test_fully_unsafe_correlation_id_falls_back_to_the_sentinel(
    middleware_client: TestClient,
) -> None:
    # Sanitizing to an empty string must not yield an empty header value.
    response = middleware_client.get("/echo", headers={CORRELATION_ID_HEADER: "$$$"})

    assert response.json()["correlation_id"] == UNSET
    assert CORRELATION_ID_HEADER not in response.headers


def test_client_trace_id_is_echoed_alongside(middleware_client: TestClient) -> None:
    response = middleware_client.get(
        "/echo", headers={CLIENT_TRACE_ID_HEADER: "trace-1"}
    )

    assert response.headers[CLIENT_TRACE_ID_HEADER] == "trace-1"


def test_endpoint_and_method_are_bound(middleware_client: TestClient) -> None:
    body = middleware_client.get("/echo").json()

    assert body["endpoint"] == "/echo"
    assert body["method"] == "GET"


def test_correlation_headers_carry_the_id_downstream(
    middleware_client: TestClient,
) -> None:
    body = middleware_client.get(
        "/echo", headers={CORRELATION_ID_HEADER: CORRELATION_ID}
    ).json()

    assert body["outgoing"] == {CORRELATION_ID_HEADER: CORRELATION_ID}


def test_correlation_headers_are_empty_without_an_id(
    middleware_client: TestClient,
) -> None:
    assert middleware_client.get("/echo").json()["outgoing"] == {}


def test_correlation_headers_are_empty_outside_a_request() -> None:
    # The HSM key cleanup runner calls out with no request in flight.
    assert correlation_headers() == {}


def test_context_is_restored_for_an_unhandled_exception(
    middleware_client: TestClient,
) -> None:
    response = middleware_client.get(
        "/boom", headers={CORRELATION_ID_HEADER: CORRELATION_ID}
    )

    assert response.status_code == 500
    assert response.json()["correlation_id"] == CORRELATION_ID
    assert response.json()["request_id"] != UNSET


def test_correlation_id_is_echoed_on_a_500(middleware_client: TestClient) -> None:
    response = middleware_client.get(
        "/boom", headers={CORRELATION_ID_HEADER: CORRELATION_ID}
    )

    assert response.headers[CORRELATION_ID_HEADER] == CORRELATION_ID
    assert response.headers[REQUEST_ID_HEADER]


def test_context_does_not_leak_between_requests(middleware_client: TestClient) -> None:
    middleware_client.get("/echo", headers={CORRELATION_ID_HEADER: CORRELATION_ID})

    assert middleware_client.get("/echo").json()["correlation_id"] == UNSET
    assert correlation_id_var.get() == UNSET


def test_each_request_gets_a_distinct_request_id(middleware_client: TestClient) -> None:
    first = middleware_client.get("/echo").headers[REQUEST_ID_HEADER]
    second = middleware_client.get("/echo").headers[REQUEST_ID_HEADER]

    assert first != second


def test_correlation_id_reaches_the_formatted_log_record() -> None:
    """The formatter must collect correlation_id, not just the middleware bind it.

    Reading the context var directly would pass even if ``_collect_context``
    never emitted the field, so assert on real formatter output.
    """
    record = logging.LogRecord(
        name="app.test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="hi",
        args=(),
        exc_info=None,
    )
    token = correlation_id_var.set(CORRELATION_ID)
    try:
        out = json.loads(JsonFormatter(include_traces=False).format(record))
    finally:
        correlation_id_var.reset(token)

    assert out["message"]["correlation_id"] == CORRELATION_ID


def test_correlation_id_survives_per_stream_field_routing() -> None:
    # correlation_id is in _ALWAYS_KEEP_FIELDS, so stream routing must not drop it.
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.addFilter(AppFilter())
    handler.setFormatter(JsonFormatter(include_traces=False, stream=LoggingStreams.APP))

    logger = logging.getLogger("app.test_correlation_routing")
    logger.setLevel(logging.DEBUG)
    logger.handlers = [handler]
    logger.propagate = False

    token = correlation_id_var.set(CORRELATION_ID)
    try:
        log_event(logger, SYS_APP_STARTED, "started")
    finally:
        correlation_id_var.reset(token)
        logger.handlers = []

    message = json.loads(buf.getvalue().splitlines()[0])["message"]
    assert message["correlation_id"] == CORRELATION_ID
