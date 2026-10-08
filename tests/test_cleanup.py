from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from app import cleanup


@pytest.fixture
def service() -> Iterator[MagicMock]:
    with patch("app.cleanup.container.get_hsm_key_cleanup_service") as get_service:
        yield get_service.return_value


def test_main_returns_zero_on_success(service: MagicMock) -> None:
    service.cleanup_expired_keys.return_value = 3

    assert cleanup.main() == 0

    service.cleanup_expired_keys.assert_called_once_with()


def test_main_returns_one_on_failure(service: MagicMock) -> None:
    service.cleanup_expired_keys.side_effect = RuntimeError("boom")

    assert cleanup.main() == 1
