"""Asserts the OpenAPI schema carries the extensions installed by the app."""

from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI

from app.application import SCOPES_EXTENSION, setup_fastapi
from app.config import get_config
from app.models.auth.data import SCOPE_DESCRIPTIONS, AuthorizationScope

BuildSchema = Callable[..., dict[str, Any]]


@pytest.fixture
def build_schema(monkeypatch: pytest.MonkeyPatch) -> BuildSchema:
    def _build(
        swagger_enabled: bool = True, document_gf_headers: bool = True
    ) -> dict[str, Any]:
        uvicorn = get_config().uvicorn
        monkeypatch.setattr(uvicorn, "swagger_enabled", swagger_enabled)
        monkeypatch.setattr(uvicorn, "document_gf_headers", document_gf_headers)
        app: FastAPI = setup_fastapi()
        return app.openapi()

    return _build


def test_schema_contains_the_scope_catalogue(build_schema: BuildSchema) -> None:
    schema = build_schema()

    assert schema[SCOPES_EXTENSION] == {
        scope.value: SCOPE_DESCRIPTIONS[scope] for scope in AuthorizationScope
    }


def test_schema_keeps_app_metadata(build_schema: BuildSchema) -> None:
    schema = build_schema()

    assert schema["info"]["title"] == "Pseudoniemendienst API"
    assert "Pseudoniemendienst" in schema["info"]["description"]
    assert [tag["name"] for tag in schema["tags"]][:1] == ["Service Information"]


def test_gf_header_security_schemes_when_documented(
    build_schema: BuildSchema,
) -> None:
    schema = build_schema(document_gf_headers=True)

    schemes = schema["components"]["securitySchemes"]
    assert {s["name"] for s in schemes.values() if s["type"] == "apiKey"} >= {
        "x-gf-sub",
        "x-gf-act-sub",
        "x-gf-act-cn",
        "x-gf-audience",
    }
    assert schema["security"] == [{name: [] for name in schemes}]


def test_bearer_security_scheme_when_gf_headers_not_documented(
    build_schema: BuildSchema,
) -> None:
    schema = build_schema(document_gf_headers=False)

    schemes = schema["components"]["securitySchemes"]
    assert schemes["BearerAuth"]["scheme"] == "bearer"
    assert not any(s.get("name", "").startswith("x-gf-") for s in schemes.values())


def test_schema_is_built_once(
    build_schema: BuildSchema, monkeypatch: pytest.MonkeyPatch
) -> None:
    uvicorn = get_config().uvicorn
    monkeypatch.setattr(uvicorn, "swagger_enabled", True)
    app = setup_fastapi()

    assert app.openapi() is app.openapi()
