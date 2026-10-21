"""OprfService wraps known evaluator failures, but not domain errors or unexpected ones."""

import base64
from unittest.mock import MagicMock

import pytest
import requests
from conftest import blinded_input
from jwcrypto.jwk import JWK

from app.exceptions.access import RecipientNotFoundError
from app.exceptions.pseudonym import PseudonymOperationError
from app.models.requests import BlindRequest
from app.services.hsm.client import HsmKeyNotFound
from app.services.oprf.oprf_service import OprfService

REQUEST = BlindRequest.model_validate(
    {
        "encryptedPersonalId": blinded_input(),
        "recipientOrganization": "oin:00000099000000001000",
        "recipientScope": "nvi",
    }
)
KEY = JWK(generate="oct")


def _service(evaluate_side_effect: Exception) -> OprfService:
    evaluator = MagicMock()
    evaluator.evaluate.side_effect = evaluate_side_effect
    return OprfService(evaluator)


@pytest.mark.parametrize(
    "element",
    [b"foo", bytes(32), b"\xff" * 32],
    ids=["wrong-length", "identity", "not-a-point"],
)
def test_blind_that_is_not_a_ristretto255_element_is_rejected_before_evaluation(
    element: bytes,
) -> None:
    evaluator = MagicMock()
    service = OprfService(evaluator)
    request = REQUEST.model_copy(
        update={"encryptedPersonalId": base64.urlsafe_b64encode(element).decode()}
    )

    with pytest.raises(PseudonymOperationError) as e:
        service.eval_blind(request, KEY)

    assert e.value.error_type == "invalid_blinded_input"
    evaluator.evaluate.assert_not_called()


def test_app_error_from_the_evaluator_passes_through_unwrapped() -> None:
    service = _service(RecipientNotFoundError())

    with pytest.raises(RecipientNotFoundError):
        service.eval_blind(REQUEST, KEY)


@pytest.mark.parametrize(
    "failure,error_type",
    [
        (requests.HTTPError("500 Server Error"), "hsm_operation_failed"),
        (HsmKeyNotFound("No such key"), "hsm_operation_failed"),
        (requests.ConnectionError("refused"), "hsm_unreachable"),
        (requests.ConnectTimeout("no connection in time"), "hsm_unreachable"),
        (requests.ReadTimeout("no answer in time"), "hsm_timeout"),
    ],
    ids=["refused", "key-missing", "unreachable", "connect-timeout", "read-timeout"],
)
def test_known_hsm_failure_becomes_an_evaluation_error(
    failure: Exception, error_type: str
) -> None:
    service = _service(failure)

    with pytest.raises(PseudonymOperationError) as e:
        service.eval_blind(REQUEST, KEY)

    assert e.value.error_type == error_type


def test_recipient_without_active_key_version_is_not_found() -> None:
    evaluator = MagicMock()
    evaluator.evaluate.return_value = {}
    service = OprfService(evaluator)

    with pytest.raises(RecipientNotFoundError):
        service.eval_blind(REQUEST, KEY)
