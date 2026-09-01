import logging
from collections.abc import Callable, Generator

import pytest
from fastapi.testclient import TestClient

from app.config import get_config, set_config

ENDPOINT = "/saml-exchange/reversible-pseudonym"


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
    assert "00000099000000001000" in str(getattr(record, "handelende_oin"))


def test_saml_exchange_not_mounted_when_disabled(
    saml_exchange_disabled: None, client: TestClient
) -> None:
    response = client.post(ENDPOINT, json={"foo": "bar"})
    assert response.status_code == 404
