import base64
from unittest.mock import MagicMock

import pyoprf
import pytest
from jwcrypto import jwk
from requests import ConnectionError

from app.enums.pseudonym_error_type import PseudonymErrorType
from app.exceptions.access import RecipientNotFoundError
from app.exceptions.pseudonym import (
    HsmOperationFailedError,
    HsmUnreachableError,
    InvalidBlindedInputError,
)
from app.models.oin import Oin, RecipientOrganizationOin
from app.models.requests.oprf import BlindRequest
from app.services.hsm.client import HsmKeyNotFound
from app.services.oprf.evaluators import HsmOprfEvaluator
from app.services.oprf.oprf_service import (
    _RISTRETTO255_IDENTITY,
    OprfEvalResult,
    OprfService,
)


@pytest.fixture
def blind_request(valid_organization_id: Oin) -> BlindRequest:
    data = b"test_input"
    _blind_factor, blinded_input = pyoprf.blind(data)
    return BlindRequest(
        encryptedPersonalId=base64.urlsafe_b64encode(blinded_input).decode("ascii"),
        recipientOrganization=RecipientOrganizationOin(valid_organization_id),
        recipientScope="test_scope",
    )


def test_eval_blind_should_return_jwe_with_versions(
    oprf_service: OprfService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    blind_request: BlindRequest,
    valid_organization_id: Oin,
) -> None:
    hsm_oprf_evaluator.evaluate = MagicMock(return_value={1: b"eval_result"})

    # Mock the build method directly on the service's internal jwe_token_service
    oprf_service._OprfService__jwe_token_service.build = MagicMock(
        return_value="test.jwe.token"
    )

    pub_key = jwk.JWK(kty="RSA", n="test", e="AQAB")
    result = oprf_service.eval_blind(blind_request, pub_key)

    assert isinstance(result, OprfEvalResult)
    assert result.jwe == "test.jwe.token"
    assert result.key_versions == (1,)


def test_eval_blind_should_raise_when_invalid_base64(
    oprf_service: OprfService,
    blind_request: BlindRequest,
) -> None:
    blind_request.encryptedPersonalId = "invalid-base64!!!"

    with pytest.raises(InvalidBlindedInputError) as exc_info:
        pub_key = jwk.JWK(kty="RSA", n="test", e="AQAB")
        oprf_service.eval_blind(blind_request, pub_key)

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_BLINDED_INPUT


def test_eval_blind_should_raise_when_not_ristretto255(
    oprf_service: OprfService,
    blind_request: BlindRequest,
) -> None:
    blind_request.encryptedPersonalId = base64.urlsafe_b64encode(
        _RISTRETTO255_IDENTITY
    ).decode("ascii")

    with pytest.raises(InvalidBlindedInputError) as exc_info:
        pub_key = jwk.JWK(kty="RSA", n="test", e="AQAB")
        oprf_service.eval_blind(blind_request, pub_key)

    assert exc_info.value.error_type == PseudonymErrorType.INVALID_BLINDED_INPUT


def test_eval_blind_should_raise_when_hsm_unreachable(
    oprf_service: OprfService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    blind_request: BlindRequest,
) -> None:
    hsm_oprf_evaluator.evaluate = MagicMock(
        side_effect=ConnectionError("Connection failed")
    )

    with pytest.raises(HsmUnreachableError) as exc_info:
        pub_key = jwk.JWK(kty="RSA", n="test", e="AQAB")
        oprf_service.eval_blind(blind_request, pub_key)

    assert exc_info.value.error_type == PseudonymErrorType.HSM_UNREACHABLE


def test_eval_blind_should_raise_when_hsm_key_not_found(
    oprf_service: OprfService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    blind_request: BlindRequest,
) -> None:
    hsm_oprf_evaluator.evaluate = MagicMock(side_effect=HsmKeyNotFound("Key not found"))

    with pytest.raises(HsmOperationFailedError) as exc_info:
        pub_key = jwk.JWK(kty="RSA", n="test", e="AQAB")
        oprf_service.eval_blind(blind_request, pub_key)

    assert exc_info.value.error_type == PseudonymErrorType.HSM_OPERATION_FAILED


def test_eval_blind_should_raise_when_no_active_versions(
    oprf_service: OprfService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    blind_request: BlindRequest,
) -> None:
    hsm_oprf_evaluator.evaluate = MagicMock(return_value={})

    with pytest.raises(RecipientNotFoundError):
        pub_key = jwk.JWK(kty="RSA", n="test", e="AQAB")
        oprf_service.eval_blind(blind_request, pub_key)
