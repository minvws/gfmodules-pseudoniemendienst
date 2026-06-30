from pytest import MonkeyPatch
from fastapi.testclient import TestClient


def test_health_check_all_components_healthy(
    client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.db.Database.is_healthy", lambda self: True)

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["components"]["database"] == "ok"


def test_health_check_database_unhealthy(
    client: TestClient, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.db.Database.is_healthy", lambda self: False)

    response = client.get("/health")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "error"
    assert body["components"]["database"] == "error"
