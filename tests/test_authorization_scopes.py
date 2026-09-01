from collections.abc import Callable
from typing import Any

import pytest
from starlette.testclient import TestClient

from app.models.auth.data import AuthorizationScope

Headers = dict[str, str]
HeaderBuilder = Callable[..., Headers]

OPRF_BODY = {
    "encryptedPersonalId": "Zm9v",
    "recipientOrganization": "oin:00000099000000001000",
    "recipientScope": "nvi",
}

EXCHANGE_PSEUDONYM_BODY = {
    "personalId": {"landCode": "NL", "type": "bsn", "value": "9500009012"},
    "recipientOrganization": "oin:00000099000000001000",
    "recipientScope": "nvi",
}


def test_missing_scope_header_is_rejected(
    client: TestClient, valid_headers: Headers
) -> None:
    headers = {k: v for k, v in valid_headers.items() if k != "x-gf-scope"}

    response = client.post("/oprf/eval", json=OPRF_BODY, headers=headers)

    assert response.status_code == 403


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_scope_header_is_rejected(
    client: TestClient, valid_headers: Headers, value: str
) -> None:
    response = client.post(
        "/oprf/eval", json=OPRF_BODY, headers={**valid_headers, "x-gf-scope": value}
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "value",
    [
        "prs:read",
        "prs:create prs:read",
        "prs:oprf prs:read",
        "nvi:read",
        "prs:administration_typo",
    ],
)
def test_unknown_scope_is_rejected(
    client: TestClient, valid_headers: Headers, value: str
) -> None:
    """An unrecognised scope fails header validation, so it is refused on every route,
    not only on the ones whose own requirement it fails to meet."""
    headers = {**valid_headers, "x-gf-scope": value}

    assert client.post("/oprf/eval", json=OPRF_BODY, headers=headers).status_code == 403
    assert client.get("/administration/keys", headers=headers).status_code == 403


def test_scope_header_accepts_extra_whitespace(
    client: TestClient, valid_headers: Headers
) -> None:
    headers = {**valid_headers, "x-gf-scope": "  prs:oprf   prs:pseudonym  "}

    response = client.post("/oprf/eval", json=OPRF_BODY, headers=headers)

    assert response.status_code != 403


def test_oprf_eval_requires_the_oprf_scope(
    client: TestClient, headers_with_scopes: HeaderBuilder
) -> None:
    without = headers_with_scopes(AuthorizationScope.ADMINISTRATION)
    assert client.post("/oprf/eval", json=OPRF_BODY, headers=without).status_code == 403

    granted = headers_with_scopes(AuthorizationScope.OPRF)
    assert client.post("/oprf/eval", json=OPRF_BODY, headers=granted).status_code != 403


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/administration/keys"),
        ("get", "/administration/key-versions"),
        ("post", "/administration/key-versions"),
    ],
)
def test_administration_routes_require_the_administration_scope(
    client: TestClient, headers_with_scopes: HeaderBuilder, method: str, path: str
) -> None:
    without = headers_with_scopes(
        AuthorizationScope.OPRF,
        AuthorizationScope.PSEUDONYM,
        AuthorizationScope.REVERSIBLE_PSEUDONYM,
    )
    assert client.request(method, path, headers=without).status_code == 403

    granted = headers_with_scopes(AuthorizationScope.ADMINISTRATION)
    assert client.request(method, path, headers=granted).status_code != 403


def test_test_routes_are_authenticated_but_not_scoped(
    client: TestClient, headers_with_scopes: HeaderBuilder
) -> None:
    headers = headers_with_scopes(AuthorizationScope.ADMINISTRATION)
    body = {"personalId": "NL:bsn:9500009012"}
    assert (
        client.post("/test/oprf/client", json=body, headers=headers).status_code == 200
    )

    unauthenticated = {k: v for k, v in headers.items() if k != "x-gf-sub"}
    assert (
        client.post("/test/oprf/client", json=body, headers=unauthenticated).status_code
        == 403
    )


@pytest.mark.parametrize(
    "pseudonym_type,required",
    [
        ("irreversible", AuthorizationScope.PSEUDONYM),
        ("reversible", AuthorizationScope.REVERSIBLE_PSEUDONYM),
    ],
)
def test_exchange_pseudonym_scope_follows_the_pseudonym_type(
    client: TestClient,
    headers_with_scopes: HeaderBuilder,
    pseudonym_type: str,
    required: AuthorizationScope,
) -> None:
    body = {**EXCHANGE_PSEUDONYM_BODY, "pseudonymType": pseudonym_type}
    other = (
        AuthorizationScope.REVERSIBLE_PSEUDONYM
        if required is AuthorizationScope.PSEUDONYM
        else AuthorizationScope.PSEUDONYM
    )

    without = headers_with_scopes(other, AuthorizationScope.ADMINISTRATION)
    denied = client.post("/exchange/pseudonym", json=body, headers=without)
    assert denied.status_code == 403

    granted = headers_with_scopes(required)
    allowed = client.post("/exchange/pseudonym", json=body, headers=granted)
    assert allowed.status_code != 403
