import base64
from unittest.mock import MagicMock, patch

import pytest
from requests import ConnectionError, HTTPError

from app.models.oin import Oin
from app.services.irreversible.keys import (
    HsmIrreversibleKeyOperations,
    IrreversibleKeyLabel,
    LocalIrreversibleKeyOperations,
)


def test_irreversible_key_label_str_should_format_correctly(
    valid_organization_id: Oin,
) -> None:
    label = IrreversibleKeyLabel(oin=valid_organization_id, version=1)
    expected = f"oin-{valid_organization_id.value}-irp-v1-hmac"
    assert str(label) == expected


def test_local_irreversible_key_operations_hmac_should_return_valid_hash(
    local_irreversible_key_operations: LocalIrreversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    result = local_irreversible_key_operations.hmac(
        valid_organization_id, 1, b"test_data"
    )
    assert isinstance(result, bytes)
    assert len(result) == 32  # SHA256 produces 32-byte digest


def test_local_irreversible_key_operations_hmac_should_known_answser() -> None:
    mock_oin = Oin("00000099000000001000")
    # pre computed master key
    local_master_key = "ZodqnfgZRNwTYpCU0difJi4ceqSG7JnVQkBqJUsa6uo="
    # pre computed value of the hex output of the hmac method
    expected = "7818bb33637da213389ff891ca8e7803e31a5a202a22318b55d96b75edf34199"
    local_irreversible_key_operation = LocalIrreversibleKeyOperations(
        base64.b64decode(local_master_key)
    )
    actual = local_irreversible_key_operation.hmac(mock_oin, 1, b"some-data")

    assert bytes.fromhex(expected) == actual


def test_local_irreversible_key_operations_destroy_should_return_false(
    local_irreversible_key_operations: LocalIrreversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    result = local_irreversible_key_operations.destroy(valid_organization_id, 1)
    assert result is False


@patch("app.services.irreversible.keys.HsmClient.hmac")
def test_hsm_irreversible_key_operations_hmac_should_return_result(
    mock_hmac: MagicMock,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    mock_hmac.return_value = b"test_hmac_result"

    result = hsm_irreversible_key_operations.hmac(
        valid_organization_id, 1, b"test_data"
    )

    assert result == b"test_hmac_result"
    mock_hmac.assert_called_once()


@patch("app.services.irreversible.keys.HsmClient.hmac")
def test_hsm_irreversible_key_operations_hmac_should_raise_when_hsm_unreachable(
    mock_hmac: MagicMock,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    mock_hmac.side_effect = ConnectionError("Connection failed")

    with pytest.raises(ConnectionError):
        hsm_irreversible_key_operations.hmac(valid_organization_id, 1, b"test_data")


@patch("app.services.irreversible.keys.HsmClient.hmac")
def test_hsm_irreversible_key_operations_hmac_should_raise_when_hsm_error(
    mock_hmac: MagicMock,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    mock_hmac.side_effect = HTTPError("HTTP error")

    with pytest.raises(HTTPError):
        hsm_irreversible_key_operations.hmac(valid_organization_id, 1, b"test_data")


@patch("app.services.irreversible.keys.HsmClient.destroy_if_present")
def test_hsm_irreversible_key_operations_destroy_should_call_client(
    mock_destroy_if_present: MagicMock,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    mock_destroy_if_present.return_value = True

    result = hsm_irreversible_key_operations.destroy(valid_organization_id, 1)

    assert result is True
    mock_destroy_if_present.assert_called_once_with(
        f"oin-{valid_organization_id.value}-irp-v1-hmac"
    )


@patch("app.services.irreversible.keys.HsmClient.destroy_if_present")
def test_hsm_irreversible_key_operations_destroy_should_raise_when_hsm_unreachable(
    mock_destroy_if_present: MagicMock,
    hsm_irreversible_key_operations: HsmIrreversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    mock_destroy_if_present.side_effect = ConnectionError("Connection failed")

    with pytest.raises(ConnectionError):
        hsm_irreversible_key_operations.destroy(valid_organization_id, 1)
