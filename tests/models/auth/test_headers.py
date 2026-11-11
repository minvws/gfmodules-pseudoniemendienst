import pytest
from fastapi import Request
from pydantic import ValidationError
from starlette.datastructures import Headers

from app.models.auth.data import AuthorizationScope
from app.models.auth.headers import AuthHeaders
from app.models.oin import Oin


def test_model_validate_with_valid_data(
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
) -> None:
    data = {
        "x-gf-sub": str(valid_organization_id),
        "x-gf-act-sub": str(valid_client_organization_id),
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": "prs.service",
        "x-gf-scope": "prs:oprf-pseudonym",
    }
    result = AuthHeaders.model_validate(data)
    assert result.organization_id == valid_organization_id
    assert result.client_organization_id == valid_client_organization_id
    assert result.client_organization_common_name == valid_client_common_name
    assert result.audience == "prs.service"
    assert result.scope == [AuthorizationScope.OPRF_PSEUDONYM]


def test_model_validate_with_multiple_scopes(
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
) -> None:
    data = {
        "x-gf-sub": str(valid_organization_id),
        "x-gf-act-sub": str(valid_client_organization_id),
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": "prs.service",
        "x-gf-scope": "prs:oprf-pseudonym prs:pseudonym",
    }
    result = AuthHeaders.model_validate(data)
    assert result.scope == [
        AuthorizationScope.OPRF_PSEUDONYM,
        AuthorizationScope.PSEUDONYM,
    ]


def test_model_validate_with_mixed_scopes_keeps_valid_ones(
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
) -> None:
    data = {
        "x-gf-sub": str(valid_organization_id),
        "x-gf-act-sub": str(valid_client_organization_id),
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": "prs.service",
        "x-gf-scope": "prs:oprf-pseudonym unknown:scope",
    }
    result = AuthHeaders.model_validate(data)
    assert result.scope == [AuthorizationScope.OPRF_PSEUDONYM]


@pytest.mark.parametrize("scope_value", ["", "   ", "unknown:scope1 unknown:scope2"])
def test_model_validate_with_invalid_scope_raises(
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    scope_value: str,
) -> None:
    data = {
        "x-gf-sub": str(valid_organization_id),
        "x-gf-act-sub": str(valid_client_organization_id),
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": "prs.service",
        "x-gf-scope": scope_value,
    }
    with pytest.raises(
        ValueError, match="x-gf-scope must hold at least one known scope"
    ):
        AuthHeaders.model_validate(data)


def test_from_request_with_all_headers_should_succeed(
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
) -> None:
    headers = Headers(
        {
            "x-gf-sub": str(valid_organization_id),
            "x-gf-act-sub": str(valid_client_organization_id),
            "x-gf-act-cn": valid_client_common_name,
            "x-gf-audience": "prs.service",
            "x-gf-scope": "prs:oprf-pseudonym",
        }
    )
    request = Request(scope={"type": "http", "headers": headers.raw})

    result = AuthHeaders.from_request(request)

    assert result.organization_id == valid_organization_id
    assert result.client_organization_id == valid_client_organization_id
    assert result.client_organization_common_name == valid_client_common_name
    assert result.audience == "prs.service"
    assert result.scope == [AuthorizationScope.OPRF_PSEUDONYM]


@pytest.mark.parametrize(
    "missing_header",
    ["x-gf-sub", "x-gf-act-sub", "x-gf-act-cn", "x-gf-audience"],
)
def test_from_request_missing_required_header_should_raise(
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
    valid_client_common_name: str,
    missing_header: str,
) -> None:
    headers_dict = {
        "x-gf-sub": str(valid_organization_id),
        "x-gf-act-sub": str(valid_client_organization_id),
        "x-gf-act-cn": valid_client_common_name,
        "x-gf-audience": "prs.service",
    }
    headers_dict = {k: v for k, v in headers_dict.items() if k != missing_header}

    request = Request(scope={"type": "http", "headers": Headers(headers_dict).raw})

    with pytest.raises(ValidationError):
        AuthHeaders.from_request(request)
