"""Verifies that all log streams share a single syslog channel, differentiated by stream_id."""

from typing import Any

from app.config import ConfigLogging
from app.logging.config_builder import LogConfigBuilder

_SYSLOG_HANDLERS = (
    "syslog_app",
    "syslog_siem",
    "syslog_public_inspect",
    "syslog_debug",
)


def _build(**kwargs: Any) -> dict[str, Any]:
    return LogConfigBuilder(logging_config=ConfigLogging(**kwargs)).build()


def test_no_syslog_handlers_without_syslog_path() -> None:
    conf = _build()
    assert set(conf["handlers"]) == {"console"}


def test_all_streams_share_the_single_syslog_channel() -> None:
    conf = _build(syslog_path="logserver:514")

    for name in _SYSLOG_HANDLERS:
        assert conf["handlers"][name]["address"] == ("logserver", 514)

    formatters = {conf["handlers"][name]["formatter"] for name in _SYSLOG_HANDLERS}
    stream_ids = {
        conf["formatters"][formatter].get("stream_id") for formatter in formatters
    }
    assert stream_ids == {"app", "siem", "public_inspect", "debug"}


def test_app_logger_gets_all_streams() -> None:
    conf = _build(syslog_path="logserver:514")
    assert set(conf["loggers"]["app"]["handlers"]) == {"console", *_SYSLOG_HANDLERS}


def test_application_id_is_stamped_on_all_json_formatters() -> None:
    conf = _build(syslog_path="logserver:514", application_id="pseudoniemendienst")

    for name, formatter in conf["formatters"].items():
        if name == "plain":
            assert "application_id" not in formatter
        else:
            assert formatter["application_id"] == "pseudoniemendienst"


def test_no_application_id_without_config() -> None:
    conf = _build(syslog_path="logserver:514")
    for formatter in conf["formatters"].values():
        assert "application_id" not in formatter
