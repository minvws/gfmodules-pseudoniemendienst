from unittest.mock import MagicMock, patch

import pytest

from app.config import Config, ConfigHsm, ConfigLocalKeys
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.irreversible.keys import (
    HsmIrreversibleKeyOperations,
    LocalIrreversibleKeyOperations,
)
from app.services.key_operations import KeyOperations
from app.services.oprf.evaluators import HsmOprfEvaluator, LocalOprfEvaluator
from app.services.reversible.keys import (
    HsmReversibleKeyOperations,
    LocalReversibleKeyOperations,
)


def test_from_config_should_return_hsm_operations_when_url_is_set(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    config = MagicMock(spec=Config)
    config.hsm = MagicMock(spec=ConfigHsm)
    config.hsm.url = "http://example.com"
    config.hsm.module = "some_module"
    config.hsm.slot = "some_slot"
    config.hsm.timeout = 10.0
    config.hsm.cert_file = "/path/to/cert"
    config.hsm.key_file = "/path/to/key"
    config.hsm.ca_cert_file = None

    result = KeyOperations.from_config(config, hsm_key_version_service)

    assert isinstance(result, KeyOperations)
    assert isinstance(result.oprf_evaluator, HsmOprfEvaluator)
    assert isinstance(result.reversible_keys, HsmReversibleKeyOperations)
    assert isinstance(result.irreversible_keys, HsmIrreversibleKeyOperations)


@patch(
    "app.services.key_operations._load_server_key", return_value=b"valid_oprf_key_bytes"
)
@patch(
    "app.services.key_operations._load_master_key",
    return_value=b"valid_master_key_bytes",
)
def test_from_config_should_return_local_operations_when_url_is_not_set(
    mock_load_master_key: MagicMock,
    mock_load_server_key: MagicMock,
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    config = MagicMock(spec=Config)
    config.hsm = MagicMock(spec=ConfigHsm)
    config.hsm.url = None
    config.local_keys = MagicMock(spec=ConfigLocalKeys)
    config.local_keys.master_key = MagicMock()
    config.local_keys.master_key.get_secret_value.return_value = "valid_base64_key"
    config.local_keys.oprf_server_key_file = "/path/to/oprf_key"

    result = KeyOperations.from_config(config, hsm_key_version_service)

    assert isinstance(result, KeyOperations)
    assert isinstance(result.oprf_evaluator, LocalOprfEvaluator)
    assert isinstance(result.reversible_keys, LocalReversibleKeyOperations)
    assert isinstance(result.irreversible_keys, LocalIrreversibleKeyOperations)


def test_from_config_should_raise_value_error_when_master_key_is_empty(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    config = MagicMock(spec=Config)
    config.hsm = MagicMock(spec=ConfigHsm)
    config.hsm.url = None
    config.local_keys = MagicMock(spec=ConfigLocalKeys)
    config.local_keys.master_key = MagicMock()
    config.local_keys.master_key.get_secret_value.return_value = ""
    config.local_keys.oprf_server_key_file = "/path/to/oprf_key"

    with pytest.raises(ValueError, match="local_keys.master_key is not configured"):
        KeyOperations.from_config(config, hsm_key_version_service)


def test_from_config_should_raise_value_error_when_master_key_is_too_short(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    config = MagicMock(spec=Config)
    config.hsm = MagicMock(spec=ConfigHsm)
    config.hsm.url = None
    config.local_keys = MagicMock(spec=ConfigLocalKeys)
    config.local_keys.master_key = MagicMock()
    # "test" in base64 (4 bytes when decoded, which is < 32 bytes)
    config.local_keys.master_key.get_secret_value.return_value = "dGVzdA=="
    config.local_keys.oprf_server_key_file = "/path/to/oprf_key"

    with pytest.raises(ValueError, match="local_keys.master_key is too short"):
        KeyOperations.from_config(config, hsm_key_version_service)


def test_from_config_should_raise_file_not_found_error_when_oprf_key_file_missing(
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    config = MagicMock(spec=Config)
    config.hsm = MagicMock(spec=ConfigHsm)
    config.hsm.url = None
    config.local_keys = MagicMock(spec=ConfigLocalKeys)
    config.local_keys.master_key = MagicMock()
    # 32 bytes when decoded: 44 'A' characters + 1 padding '=' = 32 null bytes (\x00 * 32)
    # Base64: 44 chars = 11 groups of 4 chars, each encoding 3 bytes = 33 bytes,
    # but the last group has padding so it's actually 32 bytes total
    config.local_keys.master_key.get_secret_value.return_value = (
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    config.local_keys.oprf_server_key_file = None

    with pytest.raises(ValueError, match="OPRF server key path is empty"):
        KeyOperations.from_config(config, hsm_key_version_service)


@patch(
    "app.services.key_operations._load_server_key",
    side_effect=ValueError("OPRF server key file is empty"),
)
@patch(
    "app.services.key_operations._load_master_key",
    return_value=b"valid_master_key_bytes",
)
def test_from_config_should_raise_value_error_when_oprf_key_file_is_empty(
    mock_load_master_key: MagicMock,
    mock_load_server_key: MagicMock,
    hsm_key_version_service: HsmKeyVersionService,
) -> None:
    config = MagicMock(spec=Config)
    config.hsm = MagicMock(spec=ConfigHsm)
    config.hsm.url = None
    config.local_keys = MagicMock(spec=ConfigLocalKeys)
    config.local_keys.master_key = MagicMock()
    config.local_keys.master_key.get_secret_value.return_value = (
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    config.local_keys.oprf_server_key_file = "/path/to/empty_oprf_key"

    with pytest.raises(ValueError, match="OPRF server key file is empty"):
        KeyOperations.from_config(config, hsm_key_version_service)
