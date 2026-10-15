"""The routing layer maps every domain exception to exactly one status code."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from app import exceptions
from app.enums.personal_id_type import PersonalIdType
from app.enums.pseudonym_error_type import PseudonymErrorType
from app.exceptions import (
    DomainError,
    HsmUnreachableError,
    InvalidPseudonymError,
    NoActiveKeyVersionError,
    NotAllowedToRequestError,
    PseudonymOperationError,
    RecipientNotFoundError,
)
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
        and cls not in (DomainError, PseudonymOperationError)
    ]


def test_every_domain_error_has_a_status_code() -> None:
    unmapped = [cls.__name__ for cls in _all_domain_errors() if cls not in STATUS_CODES]
    assert unmapped == []


def test_only_pseudonym_operation_failures_are_server_errors() -> None:
    server_errors = [cls for cls, code in STATUS_CODES.items() if code >= 500]
    assert all(issubclass(cls, PseudonymOperationError) for cls in server_errors)


def test_every_pseudonym_error_type_has_its_own_exception() -> None:
    error_types = [
        cls.error_type
        for cls in _all_domain_errors()
        if issubclass(cls, PseudonymOperationError)
    ]
    assert sorted(error_types) == sorted(PseudonymErrorType)


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

    @app.get("/unknown-recipient")
    def unknown_recipient() -> None:
        raise RecipientNotFoundError()

    @app.get("/no-active-key-version")
    def no_active_key_version() -> None:
        raise NoActiveKeyVersionError("organization has no active HSM key version")

    @app.get("/hsm-unreachable")
    def hsm_unreachable() -> None:
        raise HsmUnreachableError("connection refused")

    @app.get("/invalid-pseudonym")
    def invalid_pseudonym() -> None:
        raise InvalidPseudonymError("pseudonym integrity check failed")

    return TestClient(app)


def test_handler_answers_with_the_mapped_code_and_the_message(
    client: TestClient,
) -> None:
    response = client.get("/refuse")

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Not allowed to request personal_id_type: oprf"
    }


def test_handler_uses_the_message_given_at_raise_time(client: TestClient) -> None:
    response = client.get("/custom-message")

    assert response.status_code == 422
    assert response.json() == {"detail": "JWS expired"}


def test_no_active_key_version_answers_like_an_unknown_recipient(
    client: TestClient,
) -> None:
    no_active_key = client.get("/no-active-key-version")
    unknown_recipient = client.get("/unknown-recipient")

    assert no_active_key.status_code == unknown_recipient.status_code == 404
    assert no_active_key.json() == unknown_recipient.json()


def test_unreachable_hsm_answers_service_unavailable(client: TestClient) -> None:
    response = client.get("/hsm-unreachable")

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable"}


def test_pseudonym_error_reason_stays_out_of_the_response(client: TestClient) -> None:
    response = client.get("/invalid-pseudonym")

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid pseudonym"}
