"""The routing layer maps every domain exception to exactly one status code."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from app import exceptions
from app.enums.personal_id_type import PersonalIdType
from app.exceptions import DomainError, NotAllowedToRequestError
from app.routers.errors import (
    STATUS_CODES,
    install_domain_error_handler,
    status_code_for,
)


def _all_domain_errors() -> list[type[DomainError]]:
    return [
        cls
        for cls in vars(exceptions).values()
        if isinstance(cls, type)
        and issubclass(cls, DomainError)
        and cls is not DomainError
    ]


def test_every_domain_error_has_a_status_code() -> None:
    unmapped = [cls.__name__ for cls in _all_domain_errors() if cls not in STATUS_CODES]
    assert unmapped == []


def test_every_mapped_status_code_is_a_client_error() -> None:
    assert all(400 <= code < 500 for code in STATUS_CODES.values())


def test_subclasses_inherit_the_mapping_of_their_parent() -> None:
    class MoreSpecificRecipientError(exceptions.RecipientNotFoundError):
        pass

    assert status_code_for(MoreSpecificRecipientError()) == 404


def test_unmapped_domain_error_is_an_internal_error() -> None:
    class Unmapped(DomainError):
        pass

    assert status_code_for(Unmapped()) == 500


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    install_domain_error_handler(app)

    @app.get("/refuse")
    def refuse() -> None:
        raise NotAllowedToRequestError(PersonalIdType.OPRF)

    @app.get("/custom-message")
    def custom_message() -> None:
        raise exceptions.InvalidJwsError("JWS expired")

    return TestClient(app)


def test_handler_answers_with_the_mapped_code_and_the_message(
    client: TestClient,
) -> None:
    response = client.get("/refuse")

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Not allowed to request personal_id_type: oprf"
    }


def test_handler_uses_the_message_given_at_raise_time(client: TestClient) -> None:
    response = client.get("/custom-message")

    assert response.status_code == 422
    assert response.json() == {"detail": "JWS expired"}
