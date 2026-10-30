from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient


@patch("app.routers.default.load_version_json")
def test_get_version_json_should_return_version(
    mock_load_version: MagicMock,
    client: TestClient,
) -> None:
    mock_load_version.return_value = {"version": "1.0.0", "git_ref": "abc123"}

    response = client.get("/version.json")

    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "1.0.0"
    assert data["git_ref"] == "abc123"
    assert "features" in data


@patch("app.routers.default.load_version_json")
def test_get_version_json_should_return_404_when_no_version(
    mock_load_version: MagicMock,
    client: TestClient,
) -> None:
    mock_load_version.return_value = None

    response = client.get("/version.json")

    assert response.status_code == 404
