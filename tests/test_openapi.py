import importlib
from typing import Any

import inject
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import get_config, set_config
from app.container import container_config
from app.models.auth.headers import (
    AUTH_HEADER_X_GF_AUDIENCE,
    AUTH_HEADER_X_GF_OIN,
    AUTH_HEADER_X_FORWARDED_TLS_CLIENT_CERT,
)


def _build_app_with_auth_headers_in_openapi(
    include_auth_headers: bool,
) -> FastAPI:
    original_config = get_config().model_copy(deep=True)
    try:
        config = original_config.model_copy(deep=True)
        config.development.include_auth_headers_in_openapi = include_auth_headers
        set_config(config)

        if inject.is_configured():
            inject.configure(container_config, clear=True)
        else:
            inject.configure(container_config)

        import app.auth as auth_module
        import app.application as application_module
        import app.routers.administration.key as key_router_module
        import app.routers.test_oprf as test_oprf_router_module

        importlib.reload(auth_module)
        importlib.reload(test_oprf_router_module)
        importlib.reload(key_router_module)
        importlib.reload(application_module)

        return application_module.create_fastapi_app()

    finally:
        import app.auth as auth_module
        import app.application as application_module
        import app.routers.administration.key as key_router_module
        import app.routers.test_oprf as test_oprf_router_module

        set_config(original_config)
        importlib.reload(auth_module)
        importlib.reload(test_oprf_router_module)
        importlib.reload(key_router_module)
        importlib.reload(application_module)
        if inject.is_configured():
            inject.configure(container_config, clear=True)


def _get_header_names(schema: dict[str, Any], path: str, method: str) -> set[str]:
    parameters = schema["paths"][path][method].get("parameters", [])
    return {
        param["name"]
        for param in parameters
        if isinstance(param, dict) and param.get("in") == "header"
    }


def test_openapi_includes_hsm_key_version_request_descriptions(app: FastAPI) -> None:
    schema = app.openapi()

    hsm_schema = schema["components"]["schemas"]["HsmKeyVersionRequest"]
    hsm_update_schema = schema["components"]["schemas"]["HsmKeyVersionUpdateRequest"]
    assert "from_dt is validated against the current UTC timestamp" in str(
        hsm_schema["x-temporal-constraints"]
    )
    assert (
        "timezone offset" in hsm_schema["properties"]["from_dt"]["description"].lower()
    )
    assert (
        "timezone offset"
        in hsm_update_schema["properties"]["until_dt"]["description"].lower()
    )
    assert "x-supported-timezones" in hsm_schema
    assert (
        "until_dt must be at or after from_dt (or current UTC when from_dt is "
        "omitted)" in str(hsm_schema["x-temporal-constraints"])
    )
    assert hsm_schema["properties"]["from_dt"]["description"] != ""
    assert hsm_schema["properties"]["until_dt"]["description"] != ""
    assert hsm_update_schema["properties"]["until_dt"]["description"] != ""


def test_openapi_includes_hsm_key_version_examples(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    payload = response.json()
    hsm_schema = payload["components"]["schemas"]["HsmKeyVersionRequest"]
    hsm_update_schema = payload["components"]["schemas"]["HsmKeyVersionUpdateRequest"]

    assert "x-temporal-constraints" in hsm_schema
    assert hsm_schema["x-temporal-constraints"] == [
        "from_dt is validated against the current UTC timestamp",
        "until_dt must be at or after from_dt (or current UTC when from_dt is omitted)",
        "timezone offset is required for from_dt and until_dt (RFC3339 date-time format)",
    ]
    assert "x-supported-timezones" in hsm_schema
    assert hsm_update_schema["x-temporal-constraints"] == [
        "timezone offset is required for until_dt (RFC3339 date-time format)",
    ]
    assert hsm_schema["properties"]["from_dt"]["description"] is not None
    assert hsm_update_schema["properties"]["until_dt"]["description"] is not None


def test_openapi_includes_auth_headers(app: FastAPI) -> None:
    schema = app.openapi()

    parameters = schema["paths"]["/oprf/eval"]["post"]["parameters"]
    header_params = {
        param["name"]
        for param in parameters
        if isinstance(param, dict) and param.get("in") == "header"
    }

    assert AUTH_HEADER_X_GF_OIN in header_params
    assert AUTH_HEADER_X_GF_AUDIENCE in header_params


def test_openapi_includes_mtls_header_on_register_certificate(app: FastAPI) -> None:
    schema = app.openapi()

    header_params = _get_header_names(
        schema, "/administration/register/certificate", "post"
    )

    assert (
        AUTH_HEADER_X_FORWARDED_TLS_CLIENT_CERT in header_params
        or "mtls-headers" in header_params
    )


def test_openapi_includes_mtls_header_on_test_mtls(app: FastAPI) -> None:
    schema = app.openapi()

    header_params = _get_header_names(schema, "/test/mtls", "get")

    assert (
        AUTH_HEADER_X_FORWARDED_TLS_CLIENT_CERT in header_params
        or "mtls-headers" in header_params
    )


def test_openapi_includes_test_routes_when_enabled(app: FastAPI) -> None:
    schema = app.openapi()

    assert any(path.startswith("/test/") for path in schema["paths"])


def test_openapi_hides_auth_headers_when_disabled() -> None:
    schema = _build_app_with_auth_headers_in_openapi(False).openapi()

    assert AUTH_HEADER_X_GF_OIN not in _get_header_names(schema, "/oprf/eval", "post")
    assert AUTH_HEADER_X_GF_AUDIENCE not in _get_header_names(
        schema,
        "/oprf/eval",
        "post",
    )
    assert AUTH_HEADER_X_FORWARDED_TLS_CLIENT_CERT not in _get_header_names(
        schema, "/administration/register/certificate", "post"
    )
    assert "mtls-headers" not in _get_header_names(
        schema, "/administration/register/certificate", "post"
    )
    assert "mtls-headers" not in _get_header_names(schema, "/test/mtls", "get")
    assert AUTH_HEADER_X_FORWARDED_TLS_CLIENT_CERT not in _get_header_names(
        schema, "/test/mtls", "get"
    )
