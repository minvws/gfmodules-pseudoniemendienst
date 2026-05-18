import builtins
from typing import Any

import pytest
from fastapi.testclient import TestClient


def test_index_endpoint_includes_version_line(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "Version: v0.0.0" in response.text
    assert "Commit: 0000000000000000000000000" in response.text


def test_version_json_endpoint_returns_json(client: TestClient) -> None:
    response = client.get("/version.json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["version"] == "v0.0.0"
    assert body["git_ref"] == "0000000000000000000000000"


def test_index_endpoint_handles_missing_version_file(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_file_not_found(*args: Any, **kwargs: Any) -> None:
        raise FileNotFoundError("missing")

    monkeypatch.setattr(builtins, "open", raise_file_not_found)

    response = client.get("/")

    assert response.status_code == 200
    assert "No version information found" in response.text


def test_version_json_endpoint_returns_404_when_version_file_missing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_file_not_found(*args: Any, **kwargs: Any) -> None:
        raise FileNotFoundError("missing")

    monkeypatch.setattr(builtins, "open", raise_file_not_found)

    response = client.get("/version.json")

    assert response.status_code == 404
