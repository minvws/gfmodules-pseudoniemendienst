from typing import Any

from app.config import ConfigLogging
from app.logging.filters import (
    AppFilter,
    PublicInspectFilter,
    SiemFilter,
)
from app.logging.formatter import JsonFormatter, PlainTextFormatter


class LogConfigBuilder:
    def __init__(
        self,
        logging_config: ConfigLogging,
        loglevel: str = "INFO",
    ) -> None:
        self.loglevel = loglevel
        self.logging_config = logging_config

    def _syslog_handler(
        self, path: str, formatter: str = "json", filters: list[str] | None = None
    ) -> dict[str, Any]:
        host, port_str = path.rsplit(":", 1)
        cfg: dict[str, Any] = {
            "class": "logging.handlers.SysLogHandler",
            "address": (host, int(port_str)),
            "formatter": formatter,
        }
        if filters:
            cfg["filters"] = filters
        return cfg

    def build(self) -> dict[str, Any]:
        if self.logging_config.debug_logs_in_console:
            console: dict[str, Any] = {
                "class": "logging.StreamHandler",
                "level": "DEBUG",
                "formatter": "plain",
                "stream": "ext://sys.stdout",
            }
        else:
            console = {
                "class": "logging.StreamHandler",
                "level": self.loglevel,
                "formatter": "json_traces"
                if self.logging_config.include_traces
                else "json",
                "filters": ["app_filter"],
                "stream": "ext://sys.stdout",
            }

        conf: dict[str, Any] = {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {
                "app_filter": {"()": AppFilter},
                "siem_filter": {"()": SiemFilter},
                "public_inspect_filter": {"()": PublicInspectFilter},
            },
            "formatters": {
                "json": {
                    "()": JsonFormatter,
                    "include_traces": False,
                },
                "json_traces": {
                    "()": JsonFormatter,
                    "include_traces": True,
                },
                "plain": {
                    "()": PlainTextFormatter,
                },
            },
            "handlers": {
                "console": console,
            },
            "loggers": {
                "app": {
                    "handlers": ["console"],
                    "level": self.loglevel,
                    "propagate": False,
                },
                "uvicorn": {
                    "handlers": ["console"],
                    "level": self.loglevel,
                    "propagate": False,
                },
                "uvicorn.error": {
                    "handlers": ["console"],
                    "level": self.loglevel,
                    "propagate": False,
                },
                # uvicorn.access is disabled as RequestContextMiddleware handles access logs
                "uvicorn.access": {
                    "handlers": [],
                    "level": "CRITICAL",
                    "propagate": False,
                },
            },
            "root": {"handlers": ["console"], "level": self.loglevel},
        }

        self._add_log_handlers(conf)

        return conf

    def _add_log_handlers(self, conf: dict[str, Any]) -> None:
        app_logger_handlers = conf["loggers"]["app"]["handlers"]
        uvicorn_handlers = conf["loggers"]["uvicorn"]["handlers"]
        uvicorn_error_handlers = conf["loggers"]["uvicorn.error"]["handlers"]

        if self.logging_config.app_path:
            conf["handlers"]["app_syslog"] = self._syslog_handler(
                self.logging_config.app_path, filters=["app_filter"]
            )
            app_logger_handlers.append("app_syslog")
            uvicorn_handlers.append("app_syslog")
            uvicorn_error_handlers.append("app_syslog")

        if self.logging_config.siem_path:
            conf["handlers"]["siem"] = self._syslog_handler(
                self.logging_config.siem_path, filters=["siem_filter"]
            )
            app_logger_handlers.append("siem")

        if self.logging_config.public_inspect_path:
            conf["handlers"]["public_inspect"] = self._syslog_handler(
                self.logging_config.public_inspect_path,
                filters=["public_inspect_filter"],
            )
            app_logger_handlers.append("public_inspect")

        if self.logging_config.debug_path:
            conf["handlers"]["debug"] = self._syslog_handler(
                self.logging_config.debug_path, formatter="json_traces"
            )
            app_logger_handlers.append("debug")
            uvicorn_handlers.append("debug")
            uvicorn_error_handlers.append("debug")
            conf["root"]["handlers"].append("debug")
