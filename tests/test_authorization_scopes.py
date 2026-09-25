from collections.abc import Callable

import pytest
from starlette.testclient import TestClient

from app.db.models import OrganizationEntity
from app.models.auth.data import AuthorizationScope

Headers = dict[str, str]
HeaderBuilder = Callable[..., Headers]

OPRF_BODY = {
    "encryptedPersonalId": "Zm9v",
    "recipientOrganization": "oin:00000099000000001000",
    "recipientScope": "nvi",
}

REVERSIBLE_PSEUDONYM_BODY = {
    "personalId": {"landCode": "NL", "type": "bsn", "value": "9500009012"},
    "recipientOrganization": "oin:00000099000000001000",
    "recipientScope": "nvi",
}


@pytest.fixture(autouse=True)
def _caller_organization(persisted_organization: OrganizationEntity) -> None:
    """A request that passes the scope check goes on to look up the caller in the
    database, so the organization the headers name has to exist. Otherwise every
    granted request answers 403 "Organization does not exist" and the tests could
    not tell it apart from a scope refusal."""


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
        "nvi:read",
        "prs:administration_typo",
    ],
)
def test_scope_header_without_a_known_scope_is_rejected(
    client: TestClient, valid_headers: Headers, value: str
) -> None:
    """A token that grants this service nothing is refused up front, on every route,
    rather than left to fail the requirement of each individual one."""
    headers = {**valid_headers, "x-gf-scope": value}

    assert client.post("/oprf/eval", json=OPRF_BODY, headers=headers).status_code == 403
    assert client.get("/administration/keys", headers=headers).status_code == 403


@pytest.mark.parametrize(
    "value",
    [
        "prs:oprf-pseudonym prs:read",
        "nvi:read prs:oprf-pseudonym",
        "nvi:read prs:oprf-pseudonym lmr:write",
    ],
)
def test_unknown_scopes_are_ignored_alongside_a_known_one(
    client: TestClient, valid_headers: Headers, value: str
) -> None:
    """An access token may carry scopes belonging to other services. Those must not
    fail the request, and must not grant anything here either."""
    headers = {**valid_headers, "x-gf-scope": value}

    assert client.post("/oprf/eval", json=OPRF_BODY, headers=headers).status_code != 403
    assert client.get("/administration/keys", headers=headers).status_code == 403


def test_scope_header_accepts_extra_whitespace(
    client: TestClient, valid_headers: Headers
) -> None:
    headers = {**valid_headers, "x-gf-scope": "  prs:oprf-pseudonym   prs:pseudonym  "}

    response = client.post("/oprf/eval", json=OPRF_BODY, headers=headers)

    assert response.status_code != 403


def test_oprf_eval_requires_the_oprf_scope(
    client: TestClient, headers_with_scopes: HeaderBuilder
) -> None:
    without = headers_with_scopes(AuthorizationScope.ADMINISTRATION)
    assert client.post("/oprf/eval", json=OPRF_BODY, headers=without).status_code == 403

    granted = headers_with_scopes(AuthorizationScope.OPRF_PSEUDONYM)
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
        AuthorizationScope.OPRF_PSEUDONYM,
        AuthorizationScope.PSEUDONYM,
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


def test_exchange_reversible_pseudonym_requires_the_pseudonym_scope(
    client: TestClient, headers_with_scopes: HeaderBuilder
) -> None:
    without = headers_with_scopes(
        AuthorizationScope.OPRF_PSEUDONYM, AuthorizationScope.ADMINISTRATION
    )
    denied = client.post(
        "/exchange/reversible-pseudonym",
        json=REVERSIBLE_PSEUDONYM_BODY,
        headers=without,
    )
    assert denied.status_code == 403

    granted = headers_with_scopes(AuthorizationScope.PSEUDONYM)
    allowed = client.post(
        "/exchange/reversible-pseudonym",
        json=REVERSIBLE_PSEUDONYM_BODY,
        headers=granted,
    )
    # A policy refusal is also 403, so tell the two apart by the message: the
    # scope check answers "Unauthorized request", the router never does.
    assert allowed.json().get("detail") != "Unauthorized request"
