from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from app import cleanup


@pytest.fixture
def config() -> Iterator[MagicMock]:
    with patch("app.cleanup.get_config") as get_config:
        get_config.return_value.oprf.hsm_url = "https://hsm.local"
        yield get_config.return_value


@pytest.fixture
def service() -> Iterator[MagicMock]:
    with patch("app.cleanup.container.get_hsm_key_cleanup_service") as get_service:
        yield get_service.return_value


def test_main_returns_zero_on_success(config: MagicMock, service: MagicMock) -> None:
    service.cleanup_expired_keys.return_value = 3

    assert cleanup.main() == 0

    service.cleanup_expired_keys.assert_called_once_with()


def test_main_returns_one_on_failure(config: MagicMock, service: MagicMock) -> None:
    service.cleanup_expired_keys.side_effect = RuntimeError("boom")

    assert cleanup.main() == 1


@pytest.mark.parametrize("hsm_url", ["", None])
def test_main_skips_when_hsm_not_configured(
    config: MagicMock, service: MagicMock, hsm_url: str | None
) -> None:
    config.oprf.hsm_url = hsm_url

    assert cleanup.main() == 0

    service.cleanup_expired_keys.assert_not_called()
