from unittest.mock import MagicMock, patch

from app import cleanup


def test_main_returns_zero_on_success() -> None:
    service = MagicMock()
    service.cleanup_expired_keys.return_value = 3

    with patch(
        "app.cleanup.container.get_hsm_key_cleanup_service", return_value=service
    ):
        assert cleanup.main() == 0

    service.cleanup_expired_keys.assert_called_once_with()


def test_main_returns_one_on_failure() -> None:
    service = MagicMock()
    service.cleanup_expired_keys.side_effect = RuntimeError("boom")

    with patch(
        "app.cleanup.container.get_hsm_key_cleanup_service", return_value=service
    ):
        assert cleanup.main() == 1
