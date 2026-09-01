from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

from app.config import ConfigOprf
from app.db.db import Database
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.entities.organization import Organization
from app.db.repositories.org_repository import OrgRepository
from app.db.session import DbSession
from app.models.oin import Oin
from app.rid import RidUsage
from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.hsm_key_version_service import HsmKeyVersionService

TEST_OIN = Oin("00000099000000001000")
TEST_OIN_EXPIRED_OTHER = Oin("00000099000001001000")
TEST_OIN_ACTIVE = Oin("00000099000001000000")
TEST_OIN_REMOVED = Oin("00000099000001003000")
TEST_OIN_111 = Oin("00000099000000011000")


@dataclass(frozen=True)
class HsmKeyVersionData:
    oin: Oin
    version: int
    from_delta: timedelta
    until_delta: timedelta | None
    removed: bool


def _get_or_create_organization(session: DbSession, oin: Oin) -> Organization:
    org: Organization | None = session.get_repository(OrgRepository).get_by_oin(oin)
    if org is None:
        org = Organization(
            oin=oin,
            name=f"org-{oin.value}",
            max_rid_usage=RidUsage.IrreversiblePseudonym.value,
        )
        session.add(org)
        session.flush()
    return org


def _add(
    db: Database, oin: Oin, **kwargs: object
) -> tuple[HsmKeyVersion, Organization]:
    with db.get_db_session() as session:
        org = _get_or_create_organization(session, oin)
        version = HsmKeyVersion(organization_id=org.id, **kwargs)
        session.add(version)
        session.commit()
    return version, org


def _hsm_config() -> ConfigOprf:
    return ConfigOprf(
        hsm_url="https://hsm.local", hsm_module="softhsm", hsm_slot="SoftHSMLabel"
    )


@pytest.mark.parametrize(
    "rows, expected_cleaned, expected_labels, expected_active_versions, removed_version_indexes",
    [
        pytest.param(
            [
                HsmKeyVersionData(
                    TEST_OIN, 1, timedelta(days=10), timedelta(days=1), False
                ),
                HsmKeyVersionData(
                    TEST_OIN_EXPIRED_OTHER,
                    1,
                    timedelta(days=10),
                    timedelta(days=2),
                    False,
                ),
                HsmKeyVersionData(TEST_OIN_ACTIVE, 2, timedelta(days=1), None, False),
                HsmKeyVersionData(
                    TEST_OIN_ACTIVE, 3, timedelta(days=5), timedelta(days=1), True
                ),
            ],
            2,
            {
                f"oin-{TEST_OIN}-v1",
                f"oin-{TEST_OIN_EXPIRED_OTHER}-v1",
            },
            {TEST_OIN_ACTIVE: {2}},
            (),
            id="mixed_with_active_key",
        ),
        pytest.param(
            [HsmKeyVersionData(TEST_OIN, 1, timedelta(days=1), timedelta(0), False)],
            1,
            {f"oin-{TEST_OIN}-v1"},
            {},
            (0,),
            id="until_dt_equal_to_now",
        ),
    ],
)
def test_cleanup_removes_expired_keys_from_hsm_and_db(
    database: Database,
    rows: list[HsmKeyVersionData],
    expected_cleaned: int,
    expected_labels: set[str],
    expected_active_versions: dict[Oin, set[int]],
    removed_version_indexes: tuple[int, ...],
) -> None:
    now = datetime.now(timezone.utc)
    versions: list[HsmKeyVersion] = []
    organization_ids: dict[Oin, UUID] = {}

    for row in rows:
        created, org = _add(
            database,
            oin=row.oin,
            version=row.version,
            from_dt=now - row.from_delta,
            until_dt=now - row.until_delta if row.until_delta is not None else None,
            removed=row.removed,
        )
        organization_ids.setdefault(row.oin, org.id)
        versions.append(created)

    service = HsmKeyCleanupService(
        _hsm_config(),
        HsmKeyVersionService(database),
    )

    with (
        # Keep the service's notion of "now" fixed to the test timestamp.
        patch(
            "app.services.hsm_key_version_service.datetime",
            SimpleNamespace(now=lambda tz=None: now),
        ),
        patch(
            "app.services.hsm_key_cleanup_service.requests.post",
            return_value=MagicMock(),
        ) as post,
    ):
        cleaned = service.cleanup_expired_keys()

    assert cleaned == expected_cleaned

    # The right keys are destroyed in the HSM, by their stored label.
    labels = {call.kwargs["json"]["label"] for call in post.call_args_list}
    assert labels == expected_labels
    urls = {call.args[0] for call in post.call_args_list}
    assert urls == {"https://hsm.local/hsm/softhsm/SoftHSMLabel/destroy"}

    version_service = HsmKeyVersionService(database)
    for oin in organization_ids:
        active = {
            v.version
            for v in version_service.get_active_versions_by_organization_id(
                organization_ids[oin]
            )
        }
        assert active == expected_active_versions.get(oin, set())

    # Nothing expired remains.
    assert version_service.get_expired_versions(at=now) == []

    for index in removed_version_indexes:
        removed_version = version_service.get_version(versions[index].id)
        assert removed_version is not None
        assert removed_version.removed is True


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
        ConfigOprf(hsm_url=None),
        HsmKeyVersionService(database),
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

    service = HsmKeyCleanupService(
        _hsm_config(),
        HsmKeyVersionService(database),
    )

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
    assert len(expired) == 1
    with database.get_db_session() as session:
        org = (
            session.query(Organization)
            .filter(Organization.id == expired[0].organization_id)
            .one()
        )
    assert org.oin == TEST_OIN_111


@pytest.mark.parametrize("hsm_url", ["", None])
def test_cleanup_skips_for_empty_or_missing_hsm_url(
    database: Database, hsm_url: str | None
) -> None:
    service = HsmKeyCleanupService(
        ConfigOprf(hsm_url=hsm_url),
        HsmKeyVersionService(database),
    )
    with patch("app.services.hsm_key_cleanup_service.requests.post") as post:
        assert service.cleanup_expired_keys() == 0
    post.assert_not_called()
