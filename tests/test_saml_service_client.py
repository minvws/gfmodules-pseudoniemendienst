from typing import Any

import pytest
import requests

from app.services.saml.client import SamlServiceClient, SamlServiceError


class _FakeResponse:
    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return self._body


def test_client_passes_mtls_options_to_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _FakeResponse:
        captured["url"] = url
        captured.update(kwargs)
        return _FakeResponse(200, {"ok": True})

    client = SamlServiceClient(
        url="https://prs-saml:8504/",
        timeout=2.5,
        cert_file="client.crt",
        key_file="client.key",
        ca_cert_file="ca.crt",
    )
    monkeypatch.setattr(client._session, "post", fake_post)

    assert client.decrypt({"foo": "bar"}) == {"ok": True}

    assert captured["url"] == "https://prs-saml:8504/saml/decrypt"
    assert captured["cert"] == ("client.crt", "client.key")
    assert captured["verify"] == "ca.crt"
    assert captured["timeout"] == 2.5


def test_client_without_mtls_verifies_default_ca(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _FakeResponse:
        captured.update(kwargs)
        return _FakeResponse(200, {})

    client = SamlServiceClient(url="http://localhost:8504")
    monkeypatch.setattr(client._session, "post", fake_post)

    client.decrypt({})
    assert captured["cert"] is None
    assert captured["verify"] is True


def test_client_requires_both_cert_and_key(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _FakeResponse:
        captured.update(kwargs)
        return _FakeResponse(200, {})

    client = SamlServiceClient(url="http://localhost:8504", cert_file="client.crt")
    monkeypatch.setattr(client._session, "post", fake_post)

    client.decrypt({})
    assert captured["cert"] is None


def test_client_raises_on_non_200(monkeypatch: pytest.MonkeyPatch) -> None:
    client = SamlServiceClient(url="http://localhost:8504")
    monkeypatch.setattr(
        client._session, "post", lambda url, **kwargs: _FakeResponse(500, {})
    )

    with pytest.raises(SamlServiceError) as exc_info:
        client.decrypt({})
    assert exc_info.value.error_type == "saml_service_error"


def test_client_raises_on_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_post(url: str, **kwargs: Any) -> _FakeResponse:
        raise requests.exceptions.ConnectionError("refused")

    client = SamlServiceClient(url="http://localhost:8504")
    monkeypatch.setattr(client._session, "post", fake_post)

    with pytest.raises(SamlServiceError) as exc_info:
        client.decrypt({})
    assert exc_info.value.error_type == "saml_service_unreachable"
