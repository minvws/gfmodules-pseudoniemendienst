from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from requests.exceptions import ConnectionError, HTTPError

from app.db.models.hsm_key_versions import HsmKeyVersionEntity
from app.db.models.organization import OrganizationEntity
from app.db.session import DbSession
from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.irreversible.keys import HsmIrreversibleKeyOperations
from app.services.oprf.evaluators import HsmOprfEvaluator
from app.services.reversible.keys import HsmReversibleKeyOperations
from app.utils.datetime import now_utc


def test_cleanup_removes_expired_keys_from_hsm_and_db(
    hsm_key_cleanup_service: HsmKeyCleanupService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    """Tests that expired keys are removed from HSM and marked as removed in DB."""

    # Mark the version as expired
    version = persisted_organization.hsm_key_versions[0]
    version.until_dt = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    # Mock the destroy methods to return True (keys destroyed successfully)
    with (
        patch.object(
            hsm_oprf_evaluator, "destroy", return_value=True
        ) as mock_oprf_destroy,
        patch.object(
            hsm_irreversible_key_operations, "destroy", return_value=True
        ) as mock_irp_destroy,
        patch.object(
            hsm_reversible_key_operations, "destroy", return_value=True
        ) as mock_rp_destroy,
        patch.object(
            hsm_key_version_service, "get_expired_versions", return_value=[version]
        ),
        patch.object(hsm_key_version_service, "mark_removed") as mock_mark_removed,
    ):
        # Call cleanup
        cleaned = hsm_key_cleanup_service.cleanup_expired_keys()

        # Verify cleanup count
        assert cleaned == 1

        # Verify destroy was called for all key types
        mock_oprf_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )
        mock_irp_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )
        mock_rp_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )

        # Verify version was marked as removed
        mock_mark_removed.assert_called_once_with(version.id)


def test_cleanup_destroys_every_pseudonym_key_of_the_version(
    hsm_key_cleanup_service: HsmKeyCleanupService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    """Tests that all pseudonym keys (OPRF, irreversible, reversible) are destroyed for a version."""
    from unittest.mock import patch

    # Mark the version as expired
    version = persisted_organization.hsm_key_versions[0]
    version.until_dt = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    # Mock the destroy methods to return True (keys destroyed successfully)
    with (
        patch.object(
            hsm_oprf_evaluator, "destroy", return_value=True
        ) as mock_oprf_destroy,
        patch.object(
            hsm_irreversible_key_operations, "destroy", return_value=True
        ) as mock_irp_destroy,
        patch.object(
            hsm_reversible_key_operations, "destroy", return_value=True
        ) as mock_rp_destroy,
        patch.object(
            hsm_key_version_service, "get_expired_versions", return_value=[version]
        ),
        patch.object(hsm_key_version_service, "mark_removed"),
    ):
        # Call cleanup
        cleaned = hsm_key_cleanup_service.cleanup_expired_keys()

        # Verify cleanup count
        assert cleaned == 1

        # Verify destroy was called for all key types
        # OPRF key
        mock_oprf_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )
        # Irreversible key
        mock_irp_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )
        # Reversible keys (AES and HMAC are both destroyed in one call)
        mock_rp_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )


def test_cleanup_marks_version_removed_when_no_keys_were_ever_created(
    hsm_key_cleanup_service: HsmKeyCleanupService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    """Tests that a version is marked as removed even if no HSM keys were ever created."""
    from unittest.mock import patch

    # Mark the version as expired
    version = persisted_organization.hsm_key_versions[0]
    version.until_dt = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    # Mock the destroy methods to return False (no keys were found to destroy)
    with (
        patch.object(
            hsm_oprf_evaluator, "destroy", return_value=False
        ) as mock_oprf_destroy,
        patch.object(
            hsm_irreversible_key_operations, "destroy", return_value=False
        ) as mock_irp_destroy,
        patch.object(
            hsm_reversible_key_operations, "destroy", return_value=False
        ) as mock_rp_destroy,
        patch.object(
            hsm_key_version_service, "get_expired_versions", return_value=[version]
        ),
        patch.object(hsm_key_version_service, "mark_removed") as mock_mark_removed,
    ):
        # Call cleanup
        cleaned = hsm_key_cleanup_service.cleanup_expired_keys()

        # Verify cleanup count (1 version was processed)
        assert cleaned == 1

        # Verify destroy was called for all key types (but returned False)
        mock_oprf_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )
        mock_irp_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )
        mock_rp_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )

        # Verify version was still marked as removed
        mock_mark_removed.assert_called_once_with(version.id)


def test_cleanup_marks_version_removed_without_hsm(
    hsm_key_cleanup_service: HsmKeyCleanupService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    """Tests that a version is marked as removed without HSM (local keys only)."""
    from unittest.mock import patch

    # Mark the version as expired
    version = persisted_organization.hsm_key_versions[0]
    version.until_dt = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    # Mock the destroy methods to return False (no HSM, so no keys to destroy)
    with (
        patch.object(
            hsm_oprf_evaluator, "destroy", return_value=False
        ) as mock_oprf_destroy,
        patch.object(
            hsm_irreversible_key_operations, "destroy", return_value=False
        ) as mock_irp_destroy,
        patch.object(
            hsm_reversible_key_operations, "destroy", return_value=False
        ) as mock_rp_destroy,
        patch.object(
            hsm_key_version_service, "get_expired_versions", return_value=[version]
        ),
        patch.object(hsm_key_version_service, "mark_removed") as mock_mark_removed,
    ):
        # Call cleanup
        cleaned = hsm_key_cleanup_service.cleanup_expired_keys()

        # Verify cleanup count
        assert cleaned == 1

        # Verify destroy was called for all key types (but returned False)
        mock_oprf_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )
        mock_irp_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )
        mock_rp_destroy.assert_called_once_with(
            persisted_organization.external_id, version.version
        )

        # Verify version was marked as removed
        mock_mark_removed.assert_called_once_with(version.id)


def test_cleanup_keeps_version_when_hsm_destroy_fails(
    hsm_key_cleanup_service: HsmKeyCleanupService,
    hsm_oprf_evaluator: HsmOprfEvaluator,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    hsm_key_version_service: HsmKeyVersionService,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    """Tests that a version is NOT marked as removed when HSM destroy fails."""
    # Mark the version as expired
    version = persisted_organization.hsm_key_versions[0]
    version.until_dt = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    # Mock get_expired_versions to return the expired version
    hsm_key_version_service.get_expired_versions = MagicMock(  # type: ignore
        return_value=[version]
    )

    # Mock mark_removed to track if it's called
    hsm_key_version_service.mark_removed = MagicMock()  # type: ignore

    # Mock the destroy methods to raise HTTPError (simulating HSM failure)
    # Only the first destroy call (OPRF) will be made due to the implementation
    hsm_oprf_evaluator.destroy = MagicMock(  # type: ignore
        side_effect=HTTPError("boom")
    )
    hsm_irreversible_key_operations.destroy = MagicMock()  # type: ignore
    hsm_reversible_key_operations.destroy = MagicMock()  # type: ignore

    # Call cleanup
    cleaned = hsm_key_cleanup_service.cleanup_expired_keys()

    # Verify cleanup count is 0 (failure)
    assert cleaned == 0

    # Verify destroy was called for OPRF key (but raised an exception)
    hsm_oprf_evaluator.destroy.assert_called_once_with(
        persisted_organization.external_id, version.version
    )

    # Verify destroy was NOT called for other key types (due to early failure)
    hsm_irreversible_key_operations.destroy.assert_not_called()
    hsm_reversible_key_operations.destroy.assert_not_called()

    # Verify version was NOT marked as removed
    hsm_key_version_service.mark_removed.assert_not_called()


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
    hsm_oprf_evaluator.destroy = MagicMock(return_value=True)  # type: ignore
    hsm_irreversible_key_operations.destroy = MagicMock(  # type: ignore
        return_value=True
    )
    hsm_reversible_key_operations.destroy = MagicMock(  # type: ignore
        return_value=True
    )

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
    hsm_oprf_evaluator.destroy = MagicMock(  # type: ignore
        side_effect=[True, ConnectionError("Failed")]
    )
    hsm_irreversible_key_operations.destroy = MagicMock(  # type: ignore
        side_effect=[True, ConnectionError("Failed")]
    )
    hsm_reversible_key_operations.destroy = MagicMock(  # type: ignore
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
    hsm_oprf_evaluator.destroy = MagicMock(  # type: ignore
        side_effect=ConnectionError("Failed")
    )
    hsm_irreversible_key_operations.destroy = MagicMock(  # type: ignore
        side_effect=ConnectionError("Failed")
    )
    hsm_reversible_key_operations.destroy = MagicMock(  # type: ignore
        side_effect=ConnectionError("Failed")
    )

    result = hsm_key_cleanup_service.cleanup_expired_keys()

    assert result == 0
    db_session.session.refresh(hsm_key_version)
    assert hsm_key_version.removed_at is None
