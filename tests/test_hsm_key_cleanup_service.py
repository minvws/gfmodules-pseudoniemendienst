from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from app.config import ConfigOprf
from app.db.db import Database
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.models.oin import Oin
from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.hsm_key_version_service import HsmKeyVersionService

TEST_OIN = Oin("00000099000000001000")
TEST_OIN_EXPIRED_OTHER = Oin("00000099000001001000")
TEST_OIN_ACTIVE = Oin("00000099000001000000")
TEST_OIN_REMOVED = Oin("00000099000001003000")
TEST_OIN_111 = Oin("00000099000000011000")


def _add(db: Database, oin: Oin, **kwargs: object) -> None:
    with db.get_db_session() as session:
        session.add(HsmKeyVersion(oin=oin, **kwargs))
        session.commit()


def _hsm_config() -> ConfigOprf:
    return ConfigOprf(
        hsm_url="https://hsm.local", hsm_module="softhsm", hsm_slot="SoftHSMLabel"
    )


def test_cleanup_removes_expired_keys_from_hsm_and_db(database: Database) -> None:
    now = datetime.now(timezone.utc)
    # expired, not removed -> should be cleaned up
    _add(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )
    # expired for a different org -> should be cleaned up too
    _add(
        database,
        oin=TEST_OIN_EXPIRED_OTHER,
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=2),
    )
    # active (no end date) -> must be left alone
    _add(
        database,
        oin=TEST_OIN_ACTIVE,
        version=2,
        from_dt=now - timedelta(days=1),
        until_dt=None,
    )
    # already removed -> must be ignored
    _add(
        database,
        oin=TEST_OIN_ACTIVE,
        version=3,
        from_dt=now - timedelta(days=5),
        until_dt=now - timedelta(days=1),
        removed=True,
    )

    service = HsmKeyCleanupService(_hsm_config(), HsmKeyVersionService(database))

    with patch(
        "app.services.hsm_key_cleanup_service.requests.post", return_value=MagicMock()
    ) as post:
        cleaned = service.cleanup_expired_keys()

    assert cleaned == 2

    # The right keys are destroyed in the HSM, by their stored label.
    labels = {call.kwargs["json"]["label"] for call in post.call_args_list}
    assert labels == {
        f"oin-{TEST_OIN}-v1",
        f"oin-{TEST_OIN_EXPIRED_OTHER}-v1",
    }
    urls = {call.args[0] for call in post.call_args_list}
    assert urls == {"https://hsm.local/hsm/softhsm/SoftHSMLabel/destroy"}

    # Nothing expired remains, and the active version is still active.
    version_service = HsmKeyVersionService(database)
    assert version_service.get_expired_versions() == []
    active = {
        (v.oin, v.version) for v in version_service.get_active_versions(TEST_OIN_ACTIVE)
    }
    assert active == {(TEST_OIN_ACTIVE, 2)}


def test_cleanup_skips_when_hsm_not_configured(database: Database) -> None:
    now = datetime.now(timezone.utc)
    _add(
        database,
        oin=TEST_OIN_ACTIVE,
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )

    service = HsmKeyCleanupService(
        ConfigOprf(hsm_url=None), HsmKeyVersionService(database)
    )

    with patch("app.services.hsm_key_cleanup_service.requests.post") as post:
        cleaned = service.cleanup_expired_keys()

    assert cleaned == 0
    post.assert_not_called()
    # The expired version is untouched (still expired, not removed).
    assert len(HsmKeyVersionService(database).get_expired_versions()) == 1


def test_cleanup_keeps_version_when_hsm_destroy_fails(database: Database) -> None:
    now = datetime.now(timezone.utc)
    _add(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )

    service = HsmKeyCleanupService(_hsm_config(), HsmKeyVersionService(database))

    failing = MagicMock()
    failing.raise_for_status.side_effect = requests.HTTPError("boom")

    with patch(
        "app.services.hsm_key_cleanup_service.requests.post", return_value=failing
    ):
        cleaned = service.cleanup_expired_keys()

    # HSM removal failed, so the version is left for the next run to retry.
    assert cleaned == 0
    assert len(HsmKeyVersionService(database).get_expired_versions()) == 1


def test_get_expired_versions_filters(database: Database) -> None:
    now = datetime.now(timezone.utc)
    _add(
        database,
        oin=TEST_OIN_111,
        version=1,
        from_dt=now - timedelta(days=2),
        until_dt=now - timedelta(days=1),
    )  # expired
    _add(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(days=2),
        until_dt=None,
    )  # active, no end
    _add(
        database,
        oin=TEST_OIN_EXPIRED_OTHER,
        version=1,
        from_dt=now - timedelta(days=2),
        until_dt=now + timedelta(days=1),
    )  # active, future end
    _add(
        database,
        oin=TEST_OIN_REMOVED,
        version=1,
        from_dt=now - timedelta(days=2),
        until_dt=now - timedelta(days=1),
        removed=True,
    )  # expired but already removed

    expired = HsmKeyVersionService(database).get_expired_versions()
    assert {v.oin for v in expired} == {TEST_OIN_111}


@pytest.mark.parametrize("hsm_url", ["", None])
def test_cleanup_skips_for_empty_or_missing_hsm_url(
    database: Database, hsm_url: str | None
) -> None:
    service = HsmKeyCleanupService(
        ConfigOprf(hsm_url=hsm_url), HsmKeyVersionService(database)
    )
    with patch("app.services.hsm_key_cleanup_service.requests.post") as post:
        assert service.cleanup_expired_keys() == 0
    post.assert_not_called()
