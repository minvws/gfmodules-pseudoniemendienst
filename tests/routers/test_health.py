from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient


def test_get_health_should_return_200_when_healthy(
    client: TestClient,
) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["components"]["database"] == "ok"


@patch("app.db.db.Database.health_error")
def test_get_health_should_return_503_when_database_unhealthy(
    mock_health_error: MagicMock,
    client: TestClient,
) -> None:
    # Mock the database health check to return an error
    mock_health_error.return_value = "Connection failed"

    response = client.get("/health")

    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "error"
    assert data["components"]["database"] == "error"
