from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pyoprf
import pytest

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.exceptions.access import RecipientNotFoundError
from app.models.oin import Oin
from app.services.oprf.evaluators import (
    HsmOprfEvaluator,
    LocalOprfEvaluator,
    OprfHsmKeyLabel,
)


def test_label_str_should_format_correctly(valid_organization_id: Oin) -> None:
    label = OprfHsmKeyLabel(oin=valid_organization_id, version=1)

    assert str(label) == f"oin-{valid_organization_id.value}-oprf-v1"


def test_local_oprf_evaluator_evaluate_should_return_dict_with_version_1(
    local_oprf_evaluator: LocalOprfEvaluator,
    valid_organization_id: Oin,
) -> None:
    data = b"data to evaluate"
    _factor, input = pyoprf.blind(data)

    result = local_oprf_evaluator.evaluate(valid_organization_id, input)

    assert isinstance(result, dict)
    assert 1 in result
    assert isinstance(result[1], bytes)


def test_local_oprf_evaluator_destroy_should_return_false(
    local_oprf_evaluator: LocalOprfEvaluator,
    valid_organization_id: Oin,
) -> None:
    assert local_oprf_evaluator.destroy(valid_organization_id, 1) is False


@patch("app.services.oprf.evaluators.HsmClient.oprf_evaluate")
def test_hsm_oprf_evaluator_evaluate_should_return_results_for_all_versions(
    mock_oprf_evaluate: MagicMock,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    persisted_organization: OrganizationEntity,
) -> None:
    mock_oprf_evaluate.return_value = b"test_evaluation_result"

    result = hsm_oprf_evaluator.evaluate(
        persisted_organization.external_id, b"test_blinded"
    )

    assert isinstance(result, dict)
    assert 1 in result
    assert result[1] == b"test_evaluation_result"
    mock_oprf_evaluate.assert_called_once()


@patch("app.services.oprf.evaluators.HsmClient.oprf_evaluate")
def test_hsm_oprf_evaluator_evaluate_should_return_results_for_multiple_versions(
    mock_oprf_evaluate: MagicMock,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    now = datetime.now(timezone.utc)
    version2 = HsmKeyVersionEntity(
        organization_id=persisted_organization.id,
        version=2,
        from_dt=now,
        until_dt=None,
        removed_at=None,
    )
    persisted_organization.hsm_key_versions.append(version2)
    db_session.commit()

    mock_oprf_evaluate.return_value = b"test_evaluation_result"

    result = hsm_oprf_evaluator.evaluate(
        persisted_organization.external_id, b"test_blinded"
    )

    assert isinstance(result, dict)
    assert 1 in result
    assert 2 in result
    assert result[1] == b"test_evaluation_result"
    assert result[2] == b"test_evaluation_result"
    assert mock_oprf_evaluate.call_count == 2


@patch("app.services.oprf.evaluators.HsmClient.oprf_evaluate")
@patch("app.services.oprf.evaluators.HsmClient.generate_oprf_key")
def test_hsm_oprf_evaluator_evaluate_should_generate_key_when_not_found(
    mock_generate_oprf_key: MagicMock,
    mock_oprf_evaluate: MagicMock,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    persisted_organization: OrganizationEntity,
) -> None:
    from app.services.hsm.client import HsmKeyNotFound

    mock_oprf_evaluate.side_effect = [
        HsmKeyNotFound("Key not found"),
        b"test_evaluation_result",
    ]
    mock_generate_oprf_key.return_value = True

    result = hsm_oprf_evaluator.evaluate(
        persisted_organization.external_id, b"test_blinded"
    )

    assert isinstance(result, dict)
    assert 1 in result
    assert result[1] == b"test_evaluation_result"
    mock_generate_oprf_key.assert_called_once()
    assert mock_oprf_evaluate.call_count == 2


@patch("app.services.oprf.evaluators.HsmClient.destroy_if_present")
def test_hsm_oprf_evaluator_destroy_should_call_client(
    mock_destroy_if_present,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    valid_organization_id: Oin,
) -> None:
    mock_destroy_if_present.return_value = True

    result = hsm_oprf_evaluator.destroy(valid_organization_id, 1)

    assert result is True
    mock_destroy_if_present.assert_called_once_with(
        f"oin-{valid_organization_id.value}-oprf-v1"
    )


@patch("app.services.oprf.evaluators.HsmClient.oprf_evaluate")
def test_hsm_oprf_evaluator_evaluate_should_raise_when_org_not_found(
    mock_oprf_evaluate,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    valid_organization_id_2: Oin,
) -> None:
    with pytest.raises(RecipientNotFoundError):
        hsm_oprf_evaluator.evaluate(valid_organization_id_2, b"test_blinded")
