"""OprfService wraps known evaluator failures, but not domain errors or unexpected ones."""

import base64
from unittest.mock import MagicMock

import pytest
import requests
from conftest import blinded_input
from jwcrypto.jwk import JWK

from app.exceptions import RecipientNotFoundError
from app.models.requests import BlindRequest
from app.services.hsm.client import HsmKeyNotFound
from app.services.oprf.oprf_service import OprfEvaluationError, OprfService

REQUEST = BlindRequest.model_validate(
    {
        "encryptedPersonalId": blinded_input(),
        "recipientOrganization": "oin:00000099000000001000",
        "recipientScope": "nvi",
    }
)


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
    request = REQUEST.model_copy(
        update={"encryptedPersonalId": base64.urlsafe_b64encode(element).decode()}
    )

    with pytest.raises(OprfEvaluationError) as e:
        OprfService(evaluator).eval_blind(request, JWK(generate="oct"))

    assert e.value.error_type == "invalid_blinded_input"
    evaluator.evaluate.assert_not_called()


def test_domain_error_from_the_evaluator_passes_through_unwrapped() -> None:
    with pytest.raises(RecipientNotFoundError):
        _service(RecipientNotFoundError()).eval_blind(REQUEST, JWK(generate="oct"))


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
    with pytest.raises(OprfEvaluationError) as e:
        _service(failure).eval_blind(REQUEST, JWK(generate="oct"))

    assert e.value.error_type == error_type


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("bug"), ValueError("bad local server key")],
    ids=["bug", "local-evaluator"],
)
def test_unexpected_evaluator_failure_is_not_wrapped(failure: Exception) -> None:
    with pytest.raises(type(failure)):
        _service(failure).eval_blind(REQUEST, JWK(generate="oct"))


def test_recipient_without_active_key_version_is_not_found() -> None:
    evaluator = MagicMock()
    evaluator.evaluate.return_value = {}

    with pytest.raises(RecipientNotFoundError):
        OprfService(evaluator).eval_blind(REQUEST, JWK(generate="oct"))
