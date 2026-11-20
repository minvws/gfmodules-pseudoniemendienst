from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest
from gfmodules.logging.testing import capture_records

from app import cleanup
from app.logging.events import Log


@pytest.fixture
def service() -> Iterator[MagicMock]:
    with patch("app.cleanup.container.get_hsm_key_cleanup_service") as get_service:
        yield get_service.return_value


@pytest.mark.usefixtures("unconfigured_container")
def test_main_configures_the_container_and_returns_zero_on_success() -> None:
    assert cleanup.main() == 0


def test_a_failed_run_returns_one_and_is_logged(service: MagicMock) -> None:
    service.cleanup_expired_keys.side_effect = RuntimeError("boom")

    with (
        patch("app.cleanup.application.application_init"),
        capture_records("app.cleanup") as captured,
    ):
        assert cleanup.main() == 1
        service.cleanup_expired_keys.side_effect = None
        assert cleanup.main() == 0

    (failed,) = captured.for_event(Log.KEY_CLEANUP_FAILED)
    assert failed.message["error_reason"] == "RuntimeError"
