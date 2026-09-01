from typing import Any

from fastapi import FastAPI

from app.models.auth.data import SCOPE_DESCRIPTIONS, AuthorizationScope

SCHEME_NAME = "BearerAuth"

def _security(spec: dict[str, Any], path: str, method: str) -> Any:
    return spec["paths"][path][method].get("security")


def test_all_scopes_are_published_in_the_security_scheme(app: FastAPI) -> None:
    scheme = app.openapi()["components"]["securitySchemes"][SCHEME_NAME]
    published = scheme["flows"]["clientCredentials"]["scopes"]

    assert published == {
        scope.value: SCOPE_DESCRIPTIONS[scope] for scope in AuthorizationScope
    }


def test_scheme_is_an_oauth2_client_credentials_flow(app: FastAPI) -> None:
    scheme = app.openapi()["components"]["securitySchemes"][SCHEME_NAME]

    assert scheme["type"] == "oauth2"
    assert "clientCredentials" in scheme["flows"]


def test_oprf_route_publishes_its_required_scope(app: FastAPI) -> None:
    assert _security(app.openapi(), "/oprf/eval", "post") == [
        {SCHEME_NAME: [AuthorizationScope.OPRF.value]}
    ]


def test_administration_routes_publish_their_required_scope(app: FastAPI) -> None:
    spec = app.openapi()
    expected = [{SCHEME_NAME: [AuthorizationScope.ADMINISTRATION.value]}]

    assert _security(spec, "/administration/keys", "get") == expected
    assert _security(spec, "/administration/register/certificate", "post") == expected
    assert _security(spec, "/administration/key-versions", "post") == expected


def test_exchange_pseudonym_publishes_both_pseudonym_scopes(app: FastAPI) -> None:
    assert _security(app.openapi(), "/exchange/pseudonym", "post") == [
        {
            SCHEME_NAME: [
                AuthorizationScope.PSEUDONYM.value,
                AuthorizationScope.REVERSIBLE_PSEUDONYM.value,
            ]
        }
    ]


def test_public_routes_have_no_security_requirement(app: FastAPI) -> None:
    spec = app.openapi()

    assert _security(spec, "/", "get") is None
    assert _security(spec, "/health", "get") is None
    assert _security(spec, "/version.json", "get") is None


def test_every_protected_route_requires_a_known_scope(app: FastAPI) -> None:
    known = {scope.value for scope in AuthorizationScope}

    for path, operations in app.openapi()["paths"].items():
        for method, operation in operations.items():
            security = operation.get("security")
            if security is None or path in {"/exchange/rid", "/receive"} or path.startswith("/test/"):
                continue
            scopes = security[0][SCHEME_NAME]
            assert scopes, f"{method.upper()} {path} declares no scope"
            assert set(scopes).issubset(known), f"{method.upper()} {path}: {scopes}"
