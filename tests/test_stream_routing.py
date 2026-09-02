import logging
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from typing import Any

import gfmodules.logging as gflog
import pytest
from gfmodules.logging import LogEvent, LoggingStreams, bind_context
from gfmodules.logging.testing import assert_fields_absent, capture_stream

from app.logging.events import Log

_LOGGER_NAME = "app.test_stream_routing"
_HANDELENDE_OIN = "00000099000000001000"
_DOEL_OIN = "oin:00000099000000002000"

Routed = dict[LoggingStreams, list[dict[str, Any]]]
Route = Callable[..., Routed]


@pytest.fixture
def route() -> Iterator[Route]:
    logger = logging.getLogger(_LOGGER_NAME)

    def _route(event: LogEvent, message: str = "event", **fields: Any) -> Routed:
        with ExitStack() as stack:
            routed: Routed = {
                stream: stack.enter_context(capture_stream(stream, _LOGGER_NAME))
                for stream in LoggingStreams
            }
            gflog.emit(logger, event, message, fields={**fields})
        return routed

    with bind_context(
        {
            "request_id": "req-1",
            "ip": "10.0.0.1",
            "endpoint": "/oprf/evaluate",
            "method": "POST",
            "correlation_id": "corr-1",
        }
    ):
        yield _route


class TestHealthUnhealthy:
    @pytest.fixture
    def routed(self, route: Route) -> Routed:
        return route(
            Log.HEALTH_UNHEALTHY,
            "unhealthy",
            component="database",
            status="error",
            error_detail="connection refused on 10.0.0.1:5432",
        )

    def test_siem_does_not_receive_the_error_detail(self, routed: Routed) -> None:
        assert (
            routed[LoggingStreams.APP][0]["error_detail"]
            == "connection refused on 10.0.0.1:5432"
        )
        assert_fields_absent(routed[LoggingStreams.SIEM], "error_detail")

    def test_both_streams_receive_the_component_and_status(
        self, routed: Routed
    ) -> None:
        for message in (routed[LoggingStreams.APP][0], routed[LoggingStreams.SIEM][0]):
            assert message["component"] == "database"
            assert message["status"] == "error"


class TestAppStarted:
    def test_goes_to_the_app_stream_only(self, route: Route) -> None:
        routed = route(
            Log.SYS_APP_STARTED,
            "started",
            version="v1.2.3",
            environment="test",
        )

        assert routed[LoggingStreams.APP][0]["version"] == "v1.2.3"
        assert routed[LoggingStreams.APP][0]["environment"] == "test"
        # PRS-SYS-001 has no SIEM stream per spec.
        assert routed[LoggingStreams.SIEM] == []


class TestAppStopped:
    def test_siem_receives_the_reason_but_not_the_exception(self, route: Route) -> None:
        routed = route(
            Log.SYS_APP_STOPPED,
            "stopped",
            shutdown_reason="signal:SIGTERM",
            last_exception_type="RuntimeError",
        )

        siem = routed[LoggingStreams.SIEM][0]
        assert siem["shutdown_reason"] == "signal:SIGTERM"
        assert_fields_absent(routed[LoggingStreams.SIEM], "last_exception_type")


class TestOprfEvalOk:
    @pytest.fixture
    def routed(self, route: Route) -> Routed:
        return route(
            Log.OPRF_EVAL_OK,
            "evaluated",
            handelende_oin=_HANDELENDE_OIN,
            doel_oin=_DOEL_OIN,
            oprf_secret_versie=3,
            ontvanger_pubkey_id="key-1",
        )

    def test_siem_does_not_receive_the_key_versions(self, routed: Routed) -> None:
        app_message = routed[LoggingStreams.APP][0]
        assert app_message["oprf_secret_versie"] == 3
        assert app_message["ontvanger_pubkey_id"] == "key-1"
        assert_fields_absent(
            routed[LoggingStreams.SIEM], "oprf_secret_versie", "ontvanger_pubkey_id"
        )

    def test_both_streams_receive_the_oins(self, routed: Routed) -> None:
        for message in (routed[LoggingStreams.APP][0], routed[LoggingStreams.SIEM][0]):
            assert message["handelende_oin"] == _HANDELENDE_OIN
            assert message["doel_oin"] == _DOEL_OIN

    def test_correlation_metadata_is_retained_in_every_routed_stream(
        self, routed: Routed
    ) -> None:
        for stream in (LoggingStreams.APP, LoggingStreams.SIEM):
            message = routed[stream][0]
            assert message["request_id"] == "req-1"
            assert message["correlation_id"] == "corr-1"
