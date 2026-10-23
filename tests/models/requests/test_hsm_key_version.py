from datetime import datetime, timedelta, timezone

import pytest

from app.models.requests.hsm_key_version import (
    HsmKeyVersionRequest,
    HsmKeyVersionUpdateRequest,
)


def test_hsm_key_version_request_should_validate_with_all_fields() -> None:
    request = HsmKeyVersionRequest(
        from_dt=datetime(2026, 1, 1, tzinfo=timezone.utc),
        until_dt=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    assert request.from_dt == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert request.until_dt == datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_hsm_key_version_request_should_validate_with_only_from_dt() -> None:
    request = HsmKeyVersionRequest(from_dt=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert request.from_dt == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert request.until_dt is None


def test_hsm_key_version_request_should_validate_with_no_datetimes() -> None:
    request = HsmKeyVersionRequest()
    assert request.from_dt is None
    assert request.until_dt is None


def test_hsm_key_version_request_should_raise_when_until_dt_in_past() -> None:
    with pytest.raises(ValueError, match="until_dt must be later than now"):
        HsmKeyVersionRequest(until_dt=datetime.now(timezone.utc) - timedelta(days=1))


def test_hsm_key_version_request_should_raise_when_until_dt_before_from_dt() -> None:
    # Use dates far in the future where until_dt < from_dt
    from_dt = datetime(2030, 6, 1, tzinfo=timezone.utc)
    until_dt = datetime(2030, 1, 1, tzinfo=timezone.utc)

    with pytest.raises(ValueError, match="until_dt must be later than from_dt"):
        HsmKeyVersionRequest(
            from_dt=from_dt,
            until_dt=until_dt,
        )


def test_hsm_key_version_update_request_should_validate() -> None:
    request = HsmKeyVersionUpdateRequest(
        until_dt=datetime(2027, 1, 1, tzinfo=timezone.utc)
    )
    assert request.until_dt == datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_hsm_key_version_update_request_should_validate_with_none() -> None:
    request = HsmKeyVersionUpdateRequest(until_dt=None)
    assert request.until_dt is None


def test_hsm_key_version_update_request_should_raise_when_until_dt_in_past() -> None:
    with pytest.raises(ValueError, match="until_dt must be later than now"):
        HsmKeyVersionUpdateRequest(
            until_dt=datetime.now(timezone.utc) - timedelta(days=1)
        )
