from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest
import requests

from app.config import ConfigOprf
from app.db.db import Database
from app.db.models import HsmKeyVersionEntity, OrganizationEntity
from app.db.repositories.organization_repository import OrganizationRepository
from app.db.session import DbSession
from app.models.oin import Oin
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
    removed_at: datetime | None


def _get_or_create_organization(session: DbSession, oin: Oin) -> OrganizationEntity:
    org: OrganizationEntity | None = session.get_repository(
        OrganizationRepository
    ).get_one_by_external_id(oin)
    if org is None:
        org = OrganizationEntity(
            external_id=oin,
            name=f"org-{oin.value}",
        )
        session.add(org)
        session.flush()
    return org


def _add(
    db: Database, oin: Oin, **kwargs: object
) -> tuple[HsmKeyVersionEntity, OrganizationEntity]:
    with db.get_db_session() as session:
        org = _get_or_create_organization(session, oin)
        version = HsmKeyVersionEntity(organization_id=org.id, **kwargs)
        session.add(version)
        session.commit()
    return version, org


def _hsm_config() -> ConfigOprf:
    return ConfigOprf(
        hsm_url="https://hsm.local", hsm_module="softhsm", hsm_slot="SoftHSMLabel"
    )


DESTROY_URL = "https://hsm.local/hsm/softhsm/SoftHSMLabel/destroy"


def _fake_hsm(existing: Callable[[str], bool]) -> Callable[..., MagicMock]:
    """A fake HSM API: the object search reports a label as present when
    ``existing`` says so, and destroy always succeeds."""

    def _post(url: str, json: dict[str, Any], **kwargs: Any) -> MagicMock:
        resp = MagicMock()
        if url == DESTROY_URL:
            resp.json.return_value = {"result": "ok"}
        else:
            resp.json.return_value = {
                "objects": ["obj"] if existing(json["label"]) else []
            }
        return resp

    return _post


def _destroyed_labels(post: MagicMock) -> set[str]:
    return {
        call.kwargs["json"]["label"]
        for call in post.call_args_list
        if call.args[0] == DESTROY_URL
    }


@pytest.mark.parametrize(
    "rows, expected_cleaned, expected_labels, expected_active_versions, removed_version_indexes",
    [
        pytest.param(
            [
                HsmKeyVersionData(
                    TEST_OIN, 1, timedelta(days=10), timedelta(days=1), None
                ),
                HsmKeyVersionData(
                    TEST_OIN_EXPIRED_OTHER,
                    1,
                    timedelta(days=10),
                    timedelta(days=2),
                    None,
                ),
                HsmKeyVersionData(TEST_OIN_ACTIVE, 2, timedelta(days=1), None, None),
                HsmKeyVersionData(
                    TEST_OIN_ACTIVE,
                    3,
                    timedelta(days=5),
                    timedelta(days=1),
                    datetime.now(timezone.utc),
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
            [HsmKeyVersionData(TEST_OIN, 1, timedelta(days=1), timedelta(0), None)],
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
    versions: list[HsmKeyVersionEntity] = []
    organization_ids: dict[Oin, UUID] = {}

    for row in rows:
        created, org = _add(
            database,
            oin=row.oin,
            version=row.version,
            from_dt=now - row.from_delta,
            until_dt=now - row.until_delta if row.until_delta is not None else None,
            removed_at=row.removed_at,
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
            "app.services.hsm.client.requests.post",
            side_effect=_fake_hsm(lambda label: "-rp-" not in label),
        ) as post,
    ):
        cleaned = service.cleanup_expired_keys()

    assert cleaned == expected_cleaned

    # The right keys are destroyed in the HSM, by their stored label.
    assert _destroyed_labels(post) == expected_labels

    version_service = HsmKeyVersionService(database)
    for oin, id in organization_ids.items():
        active = {
            v.version
            for v in version_service.get_active_versions_by_organization_id(id)
        }
        assert active == expected_active_versions.get(oin, set())

    # Nothing expired remains.
    assert version_service.get_expired_versions(at=now) == []

    for index in removed_version_indexes:
        removed_version = version_service.get_version(versions[index].id)
        assert removed_version is not None
        assert removed_version.removed_at is not None


def test_cleanup_destroys_reversible_pseudonym_keys_of_the_version(
    database: Database,
) -> None:
    now = datetime.now(timezone.utc)
    _add(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )
    service = HsmKeyCleanupService(_hsm_config(), HsmKeyVersionService(database))

    with patch(
        "app.services.hsm.client.requests.post", side_effect=_fake_hsm(lambda _: True)
    ) as post:
        cleaned = service.cleanup_expired_keys()

    assert cleaned == 1
    assert _destroyed_labels(post) == {
        f"oin-{TEST_OIN}-v1",
        f"oin-{TEST_OIN}-rp-v1-aes",
        f"oin-{TEST_OIN}-rp-v1-hmac",
    }


def test_cleanup_marks_version_removed_when_no_keys_were_ever_created(
    database: Database,
) -> None:
    """Keys are created on first use, so an expired version may have none."""
    now = datetime.now(timezone.utc)
    _add(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )
    service = HsmKeyCleanupService(_hsm_config(), HsmKeyVersionService(database))

    with patch(
        "app.services.hsm.client.requests.post", side_effect=_fake_hsm(lambda _: False)
    ) as post:
        cleaned = service.cleanup_expired_keys()

    assert cleaned == 1
    assert _destroyed_labels(post) == set()
    assert HsmKeyVersionService(database).get_expired_versions() == []


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

    with patch("app.services.hsm.client.requests.post") as post:
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

    with patch("app.services.hsm.client.requests.post", return_value=failing):
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
        removed_at=datetime.now(timezone.utc),
    )  # expired but already removed

    expired = HsmKeyVersionService(database).get_expired_versions()
    assert len(expired) == 1
    with database.get_db_session() as session:
        org = (
            session.query(OrganizationEntity)
            .filter(OrganizationEntity.id == expired[0].organization_id)
            .one()
        )
    assert org.external_id == TEST_OIN_111


@pytest.mark.parametrize("hsm_url", ["", None])
def test_cleanup_skips_for_empty_or_missing_hsm_url(
    database: Database, hsm_url: str | None
) -> None:
    service = HsmKeyCleanupService(
        ConfigOprf(hsm_url=hsm_url),
        HsmKeyVersionService(database),
    )
    with patch("app.services.hsm.client.requests.post") as post:
        assert service.cleanup_expired_keys() == 0
    post.assert_not_called()
