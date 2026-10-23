import pytest

from app.exceptions.access import InvalidAudienceError
from app.models.auth.headers import AuthHeaders
from app.services.auth.header import AuthHeaderService


def test_validate_should_succeed(
    auth_headers_service: AuthHeaderService,
    auth_headers: AuthHeaders,
) -> None:
    result = auth_headers_service.validate(auth_headers)
    assert result == auth_headers


def test_validate_should_raise_when_audience_not_expected(
    auth_headers_service: AuthHeaderService,
    auth_headers: AuthHeaders,
) -> None:
    wrong_headers = auth_headers.model_copy(update={"audience": "wrong.audience"})
    with pytest.raises(InvalidAudienceError):
        auth_headers_service.validate(wrong_headers)
