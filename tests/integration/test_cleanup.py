from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from app import cleanup


@pytest.fixture
def service() -> Iterator[MagicMock]:
    with patch("app.cleanup.container.get_hsm_key_cleanup_service") as get_service:
        yield get_service.return_value


@pytest.mark.usefixtures("unconfigured_container")
def test_main_configures_the_container_and_returns_zero_on_success() -> None:
    assert cleanup.main() == 0


def test_main_returns_one_on_failure(service: MagicMock) -> None:
    service.cleanup_expired_keys.side_effect = RuntimeError("boom")

    assert cleanup.main() == 1
