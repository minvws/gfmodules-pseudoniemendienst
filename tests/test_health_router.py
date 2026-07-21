import logging
from typing import Callable, List

from fastapi.testclient import TestClient
from pytest import MonkeyPatch

RecordLogs = Callable[[str], List[logging.LogRecord]]


def test_health_check_all_components_healthy(
    client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.db.Database.health_error", lambda self: None)

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["components"]["database"] == "ok"


def test_health_check_database_unhealthy(
    client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "app.db.db.Database.health_error", lambda self: "connection refused"
    )

    response = client.get("/health")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "error"
    assert body["components"]["database"] == "error"


def test_health_check_unhealthy_emits_event(
    record_logs: RecordLogs,
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    records = record_logs("app.routers.health")
    monkeypatch.setattr(
        "app.db.db.Database.health_error", lambda self: "connection refused"
    )

    client.get("/health")

    events = [r for r in records if getattr(r, "event_id", None) == "270400"]
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.ERROR
    assert record.component == "database"  # type: ignore[attr-defined]
    assert record.status == "error"  # type: ignore[attr-defined]
    assert record.error_detail == "connection refused"  # type: ignore[attr-defined]


def test_health_check_healthy_emits_no_event(
    record_logs: RecordLogs,
    client: TestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    records = record_logs("app.routers.health")
    monkeypatch.setattr("app.db.db.Database.health_error", lambda self: None)

    client.get("/health")

    assert not [r for r in records if getattr(r, "event_id", None) == "270400"]
