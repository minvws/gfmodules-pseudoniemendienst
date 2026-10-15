"""OprfService wraps unexpected evaluator failures, but not domain errors."""

import base64
from unittest.mock import MagicMock

import pytest
from conftest import blinded_input
from jwcrypto.jwk import JWK

from app.exceptions import RecipientNotFoundError
from app.models.requests import BlindRequest
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


def test_unexpected_evaluator_failure_becomes_an_evaluation_error() -> None:
    with pytest.raises(OprfEvaluationError) as e:
        _service(RuntimeError("hsm exploded")).eval_blind(REQUEST, JWK(generate="oct"))

    assert e.value.error_type == "crypto_evaluation_failure"


def test_unreachable_hsm_becomes_a_retryable_evaluation_error() -> None:
    import requests

    with pytest.raises(OprfEvaluationError) as e:
        _service(requests.exceptions.ConnectionError("refused")).eval_blind(
            REQUEST, JWK(generate="oct")
        )

    assert e.value.error_type == "hsm_unreachable"


def test_recipient_without_active_key_version_is_not_found() -> None:
    evaluator = MagicMock()
    evaluator.evaluate.return_value = {}

    with pytest.raises(RecipientNotFoundError):
        OprfService(evaluator).eval_blind(REQUEST, JWK(generate="oct"))
