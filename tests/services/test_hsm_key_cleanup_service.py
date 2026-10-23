from datetime import timedelta
from unittest.mock import MagicMock

from requests.exceptions import ConnectionError

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.irreversible.keys import HsmIrreversibleKeyOperations
from app.services.oprf.evaluators import HsmOprfEvaluator
from app.services.reversible.keys import HsmReversibleKeyOperations
from app.utils.datetime import now_utc


def test_cleanup_expired_keys_should_return_count(
    hsm_key_cleanup_service: HsmKeyCleanupService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    # Mark the version as expired
    version = persisted_organization.hsm_key_versions[0]
    version.until_dt = now_utc() - timedelta(days=1)
    db_session.commit()

    # Mock the destroy methods to return True
    hsm_oprf_evaluator.destroy = MagicMock(return_value=True)
    hsm_irreversible_key_operations.destroy = MagicMock(return_value=True)
    hsm_reversible_key_operations.destroy = MagicMock(return_value=True)

    result = hsm_key_cleanup_service.cleanup_expired_keys()

    assert result == 1


def test_cleanup_expired_keys_should_return_zero_when_no_expired(
    hsm_key_cleanup_service: HsmKeyCleanupService,
) -> None:
    result = hsm_key_cleanup_service.cleanup_expired_keys()
    assert result == 0


def test_cleanup_expired_keys_should_handle_partial_failure(
    hsm_key_cleanup_service: HsmKeyCleanupService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:

    # Mark the existing version as expired
    version_1 = persisted_organization.hsm_key_versions[0]
    version_1.until_dt = now_utc() - timedelta(days=1)

    # Add another expired version
    new_version = HsmKeyVersionEntity(
        organization_id=persisted_organization.id,
        version=2,
        from_dt=now_utc() - timedelta(days=10),
        until_dt=now_utc() - timedelta(days=5),
    )
    persisted_organization.hsm_key_versions.append(new_version)
    db_session.commit()

    # Mock destroy to always raise ConnectionError (for all versions)
    hsm_oprf_evaluator.destroy = MagicMock(
        side_effect=[True, ConnectionError("Failed")]
    )
    hsm_irreversible_key_operations.destroy = MagicMock(
        side_effect=[True, ConnectionError("Failed")]
    )
    hsm_reversible_key_operations.destroy = MagicMock(
        side_effect=[True, ConnectionError("Failed")]
    )

    result = hsm_key_cleanup_service.cleanup_expired_keys()

    assert result == 1
    db_session.session.refresh(version_1)
    db_session.session.refresh(new_version)
    assert version_1.removed_at is not None
    assert new_version.removed_at is None


def test_cleanup_expired_keys_should_return_zero_when_all_fail(
    hsm_key_cleanup_service: HsmKeyCleanupService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    # Mark the existing version as expired
    hsm_key_version = persisted_organization.hsm_key_versions[0]
    hsm_key_version.until_dt = now_utc() - timedelta(days=1)
    db_session.commit()

    # Mock all destroy calls to raise ConnectionError
    hsm_oprf_evaluator.destroy = MagicMock(side_effect=ConnectionError("Failed"))
    hsm_irreversible_key_operations.destroy = MagicMock(
        side_effect=ConnectionError("Failed")
    )
    hsm_reversible_key_operations.destroy = MagicMock(
        side_effect=ConnectionError("Failed")
    )

    result = hsm_key_cleanup_service.cleanup_expired_keys()

    assert result == 0
    db_session.session.refresh(hsm_key_version)
    assert hsm_key_version.removed_at is None
