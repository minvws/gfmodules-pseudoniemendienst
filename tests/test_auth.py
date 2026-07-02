import inject
import pytest

from app.container import container_config, get_auth_context_dependency
from app.auth import AuthContextDependency
from app.models.auth.headers import AUTH_HEADER_X_GF_AUDIENCE, AUTH_HEADER_X_GF_OIN
from app.models.oin import Oin
from app.services.auth.header import AuthHeaderService
from starlette.requests import Request


def _make_request(auth_headers: dict[str, str]) -> Request:
    normalized_headers = tuple(
        (name.encode("ascii"), value.encode("ascii"))
        for name, value in auth_headers.items()
    )
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": normalized_headers,
        }
    )


@pytest.fixture
def auth_ctx_dependency() -> AuthContextDependency:
    if inject.is_configured():
        inject.configure(container_config, clear=True)
    else:
        inject.configure(container_config)

    return get_auth_context_dependency()


def test_get_auth_ctx_uses_authenticated_audience_override(
    test_oin: Oin, auth_ctx_dependency: AuthContextDependency
) -> None:
    request = _make_request(
        {
            AUTH_HEADER_X_GF_OIN: test_oin.value,
            AUTH_HEADER_X_GF_AUDIENCE: "prs.local",
        }
    )
    service = AuthHeaderService(["prs.local"])

    ctx = auth_ctx_dependency(
        request=request,
        auth_headers_service=service,
        oin=Oin(request.headers[AUTH_HEADER_X_GF_OIN]),
        audience=request.headers[AUTH_HEADER_X_GF_AUDIENCE],
    )

    assert ctx.claims.oin == test_oin
    assert ctx.audience == "prs.local"


def test_get_auth_ctx_keeps_existing_audience_header(
    test_oin: Oin, auth_ctx_dependency: AuthContextDependency
) -> None:
    request = _make_request(
        {
            AUTH_HEADER_X_GF_OIN: test_oin.value,
            AUTH_HEADER_X_GF_AUDIENCE: "explicit",
        }
    )
    service = AuthHeaderService(["explicit"])

    ctx = auth_ctx_dependency(
        request=request,
        auth_headers_service=service,
        oin=Oin(request.headers[AUTH_HEADER_X_GF_OIN]),
        audience=request.headers[AUTH_HEADER_X_GF_AUDIENCE],
    )

    assert ctx.audience == "explicit"


def test_get_auth_ctx_with_cached_headers_uses_overrides(
    test_oin: Oin, auth_ctx_dependency: AuthContextDependency
) -> None:
    request = _make_request(
        {
            AUTH_HEADER_X_GF_OIN: test_oin.value,
            AUTH_HEADER_X_GF_AUDIENCE: "prs.local",
        }
    )
    _ = request.headers
    service = AuthHeaderService(["prs.local"])

    ctx = auth_ctx_dependency(
        request=request,
        auth_headers_service=service,
        oin=Oin(request.headers[AUTH_HEADER_X_GF_OIN]),
        audience=request.headers[AUTH_HEADER_X_GF_AUDIENCE],
    )

    assert ctx.audience == "prs.local"
