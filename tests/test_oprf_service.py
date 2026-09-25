"""OprfService wraps unexpected evaluator failures, but not domain errors."""

from unittest.mock import MagicMock

import pytest
from jwcrypto.jwk import JWK

from app.exceptions import RecipientNotFoundError
from app.models.requests import BlindRequest
from app.services.oprf.oprf_service import OprfEvaluationError, OprfService

REQUEST = BlindRequest.model_validate(
    {
        "encryptedPersonalId": "Zm9v",
        "recipientOrganization": "oin:00000099000000001000",
        "recipientScope": "nvi",
    }
)


def _service(evaluate_side_effect: Exception) -> OprfService:
    evaluator = MagicMock()
    evaluator.evaluate.side_effect = evaluate_side_effect
    return OprfService(evaluator)


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
