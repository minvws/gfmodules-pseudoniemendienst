import logging
from collections.abc import Callable, Generator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import container
from app.config import get_config, set_config
from app.services.saml.client import SamlServiceError

ENDPOINT = "/saml-exchange/reversible-pseudonym"


class _EchoSamlServiceClient:
    """Stands in for the PRS-SAML service, which currently echoes its input."""

    def decrypt(self, payload: Any) -> Any:
        return payload


class _FailingSamlServiceClient:
    def __init__(self, error_type: str) -> None:
        self.error_type = error_type

    def decrypt(self, payload: Any) -> Any:
        raise SamlServiceError(self.error_type, "boom")


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Test client with the PRS-SAML client replaced by an in-process echo."""
    app.dependency_overrides[container.get_saml_service_client] = (
        _EchoSamlServiceClient
    )
    return TestClient(app)


@pytest.fixture
def unmocked_client(app: FastAPI) -> TestClient:
    """Test client using the real SamlServiceClient, whose configured URL is
    intentionally unreachable in the test config."""
    return TestClient(app)


@pytest.fixture
def saml_exchange_disabled() -> Generator[None, None, None]:
    conf = get_config()
    previous = conf.app.enable_saml_exchange_routes
    conf.app.enable_saml_exchange_routes = False
    set_config(conf)
    yield
    conf.app.enable_saml_exchange_routes = previous
    set_config(conf)


def test_saml_exchange_echoes_object(
    client: TestClient, valid_headers: dict[str, str]
) -> None:
    payload = {
        "samlResponse": "PHNhbWxwOlJlc3BvbnNlPi4uLjwvc2FtbHA6UmVzcG9uc2U+",
        "recipientOrganization": "oin:00000099000000001000",
        "domain": "vad",
    }
    response = client.post(ENDPOINT, json=payload, headers=valid_headers)
    assert response.status_code == 200
    assert response.json() == payload


@pytest.mark.parametrize(
    "payload",
    [
        "arbitrary string",
        ["a", "list", 1],
        {"nested": {"structure": [True, None, 1.5]}},
        42,
    ],
)
def test_saml_exchange_echoes_arbitrary_json(
    client: TestClient, valid_headers: dict[str, str], payload: object
) -> None:
    response = client.post(ENDPOINT, json=payload, headers=valid_headers)
    assert response.status_code == 200
    assert response.json() == payload


def test_saml_exchange_requires_auth_headers(client: TestClient) -> None:
    response = client.post(ENDPOINT, json={"foo": "bar"})
    assert response.status_code == 403


def test_saml_exchange_rejects_missing_scope_header(
    client: TestClient, valid_headers: dict[str, str]
) -> None:
    del valid_headers["x-gf-scope"]
    response = client.post(ENDPOINT, json={"foo": "bar"}, headers=valid_headers)
    assert response.status_code == 403


def test_saml_exchange_rejects_wrong_scope(
    client: TestClient, valid_headers: dict[str, str]
) -> None:
    valid_headers["x-gf-scope"] = "nvi:read prs:some-other-scope"
    response = client.post(ENDPOINT, json={"foo": "bar"}, headers=valid_headers)
    assert response.status_code == 403


def test_saml_exchange_accepts_scope_among_others(
    client: TestClient, valid_headers: dict[str, str]
) -> None:
    valid_headers["x-gf-scope"] = "nvi:read prs:saml-reversible-pseudonym other"
    response = client.post(ENDPOINT, json={"foo": "bar"}, headers=valid_headers)
    assert response.status_code == 200


def test_saml_exchange_logs_event(
    client: TestClient,
    valid_headers: dict[str, str],
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    records = record_logs("app.routers.saml_exchange")
    response = client.post(ENDPOINT, json={"foo": "bar"}, headers=valid_headers)
    assert response.status_code == 200

    events = [r for r in records if getattr(r, "event_id", None) == "230400"]
    assert len(events) == 1
    record = events[0]
    assert record.levelno == logging.INFO
    assert "00000099000000001000" in str(record.__dict__["handelende_oin"])


def test_saml_exchange_service_error_returns_502_and_logs(
    app: FastAPI,
    valid_headers: dict[str, str],
    record_logs: Callable[[str], list[logging.LogRecord]],
) -> None:
    app.dependency_overrides[container.get_saml_service_client] = (
        lambda: _FailingSamlServiceClient("saml_service_error")
    )
    records = record_logs("app.routers.saml_exchange")

    response = TestClient(app).post(
        ENDPOINT, json={"foo": "bar"}, headers=valid_headers
    )
    assert response.status_code == 502
    assert response.json() == {"error": "SAML exchange failed"}

    events = [r for r in records if getattr(r, "event_id", None) == "230401"]
    assert len(events) == 1
    assert events[0].__dict__["error_type"] == "saml_service_error"


def test_saml_exchange_unreachable_service_returns_502(
    unmocked_client: TestClient, valid_headers: dict[str, str]
) -> None:
    response = unmocked_client.post(
        ENDPOINT, json={"foo": "bar"}, headers=valid_headers
    )
    assert response.status_code == 502


def test_saml_exchange_not_mounted_when_disabled(
    saml_exchange_disabled: None, client: TestClient
) -> None:
    response = client.post(ENDPOINT, json={"foo": "bar"})
    assert response.status_code == 404
