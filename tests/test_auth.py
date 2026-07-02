from app.auth import apply_development_auth_header_overrides, get_auth_ctx
from app.models.auth.headers import (
    AUTH_HEADER_X_GF_AUDIENCE,
    AUTH_HEADER_X_GF_OIN,
)
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


def test_get_auth_ctx_uses_authenticated_audience_override(test_oin: Oin) -> None:
    request = _make_request({AUTH_HEADER_X_GF_OIN: test_oin.value})
    apply_development_auth_header_overrides(
        request,
        override_oin=None,
        override_audience="prs.local",
    )
    service = AuthHeaderService(["prs.local"])

    ctx = get_auth_ctx(
        request=request,
        auth_headers_service=service,
    )

    assert ctx.claims.oin == test_oin
    assert ctx.audience == "prs.local"


def test_get_auth_ctx_keeps_existing_audience_header(test_oin: Oin) -> None:
    request = _make_request(
        {
            AUTH_HEADER_X_GF_OIN: test_oin.value,
            AUTH_HEADER_X_GF_AUDIENCE: "explicit",
        }
    )
    apply_development_auth_header_overrides(
        request,
        override_oin=None,
        override_audience="prs.local",
    )
    service = AuthHeaderService(["explicit"])

    ctx = get_auth_ctx(
        request=request,
        auth_headers_service=service,
    )

    assert ctx.audience == "explicit"


def test_get_auth_ctx_with_cached_headers_uses_overrides(test_oin: Oin) -> None:
    request = _make_request({AUTH_HEADER_X_GF_OIN: test_oin.value})
    _ = request.headers

    apply_development_auth_header_overrides(
        request,
        override_oin=None,
        override_audience="prs.local",
    )
    service = AuthHeaderService(["prs.local"])

    ctx = get_auth_ctx(
        request=request,
        auth_headers_service=service,
    )

    assert ctx.audience == "prs.local"
