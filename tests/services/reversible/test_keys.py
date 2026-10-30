import base64
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import ConnectionError, HTTPError

from app.models.oin import Oin
from app.services.hsm.client import HsmKeyNotFound
from app.services.reversible.keys import (
    HsmReversibleKeyOperations,
    LocalReversibleKeyOperations,
    ReversibleKeyLabel,
)


def test_reversible_key_label_str_should_format_correctly(
    valid_organization_id: Oin,
) -> None:
    # Test with hmac kind
    label_hmac = ReversibleKeyLabel(oin=valid_organization_id, version=1, kind="hmac")
    expected_hmac = f"oin-{valid_organization_id.value}-rp-v1-hmac"
    assert str(label_hmac) == expected_hmac

    # Test with aes kind
    label_aes = ReversibleKeyLabel(oin=valid_organization_id, version=1, kind="aes")
    expected_aes = f"oin-{valid_organization_id.value}-rp-v1-aes"
    assert str(label_aes) == expected_aes


def test_local_reversible_key_operations_hmac_should_return_valid_hash(
    local_reversible_key_operations: LocalReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    result = local_reversible_key_operations.hmac(
        valid_organization_id, 1, b"test_data"
    )
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_local_reversible_key_operations_hmac_should_known_answer() -> None:
    mock_oin = Oin("00000099000000001000")
    # pre computed master key with genkey(32)
    local_master_key = "syZVxBu2eCIBFEJaKgKZay_Sce8oGSUeXKCGjguv6qY="
    # pre computed value of the hex of the output of hmac method by passing
    # mock_oin, 1 and b"some-data"
    expected = "3bb5aa0f12bfe43cfb149547c5578fdded9dff25e3d3c5083fed5788c14d2f4e"
    local_reversible_key_operations = LocalReversibleKeyOperations(
        base64.urlsafe_b64decode(local_master_key)
    )

    actual = local_reversible_key_operations.hmac(mock_oin, 1, b"some-data")

    assert bytes.fromhex(expected) == actual


def test_local_reversible_key_operations_encrypt_should_return_encrypted_data(
    local_reversible_key_operations: LocalReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"1234567890123456"  # 16 bytes for AES-CBC
    data = b"test_data"

    result = local_reversible_key_operations.encrypt(valid_organization_id, 1, iv, data)

    assert isinstance(result, bytes)
    assert len(result) >= len(data)


def test_local_reversible_key_operations_encrypt_should_raise_when_invalid_iv(
    local_reversible_key_operations: LocalReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"invalid_iv"  # Not 16 bytes
    data = b"test_data"

    with pytest.raises(ValueError):
        local_reversible_key_operations.encrypt(valid_organization_id, 1, iv, data)


def test_local_reversible_key_operations_decrypt_should_return_decrypted_data(
    local_reversible_key_operations: LocalReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"1234567890123456"  # 16 bytes for AES-CBC
    original_data = b"test_data"

    # Encrypt first
    encrypted = local_reversible_key_operations.encrypt(
        valid_organization_id, 1, iv, original_data
    )

    # Decrypt
    result = local_reversible_key_operations.decrypt(
        valid_organization_id, 1, iv, encrypted
    )

    assert result == original_data


def test_local_reversible_key_operations_decrypt_should_raise_when_invalid_iv(
    local_reversible_key_operations: LocalReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"invalid_iv"  # Not 16 bytes
    data = b"test_data"

    with pytest.raises(ValueError):
        local_reversible_key_operations.decrypt(valid_organization_id, 1, iv, data)


def test_local_reversible_key_operations_destroy_should_return_false(
    local_reversible_key_operations: LocalReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    result = local_reversible_key_operations.destroy(valid_organization_id, 1)
    assert result is False


@patch("app.services.reversible.keys.HsmClient.hmac")
def test_hsm_reversible_key_operations_hmac_should_return_result(
    mock_hmac: MagicMock,
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    mock_hmac.return_value = b"test_hmac_result"

    result = hsm_reversible_key_operations.hmac(valid_organization_id, 1, b"test_data")

    assert result == b"test_hmac_result"
    mock_hmac.assert_called_once()


def test_hsm_reversible_key_operations_hmac_should_generate_keys_when_not_found(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    hsm_reversible_key_operations._client.hmac = MagicMock(
        side_effect=[
            HsmKeyNotFound("Key not found"),
            b"test_hmac_result",
        ]
    )
    hsm_reversible_key_operations._client.generate_secret_key = MagicMock(
        return_value=True
    )
    hsm_reversible_key_operations._client.generate_aes_key = MagicMock(
        return_value=True
    )

    result = hsm_reversible_key_operations.hmac(valid_organization_id, 1, b"test_data")

    assert result == b"test_hmac_result"
    hsm_reversible_key_operations._client.generate_secret_key.assert_called_once()
    assert hsm_reversible_key_operations._client.hmac.call_count == 2


def test_hsm_reversible_key_operations_encrypt_should_return_result(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"1234567890123456"  # 16 bytes
    data = b"test_data"

    hsm_reversible_key_operations._client.encrypt = MagicMock(
        return_value=b"encrypted_data"
    )

    result = hsm_reversible_key_operations.encrypt(valid_organization_id, 1, iv, data)

    assert result == b"encrypted_data"
    hsm_reversible_key_operations._client.encrypt.assert_called_once()


def test_hsm_reversible_key_operations_encrypt_should_generate_keys_when_not_found(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"1234567890123456"
    data = b"test_data"

    hsm_reversible_key_operations._client.encrypt = MagicMock(
        side_effect=[HsmKeyNotFound("Key not found"), b"encrypted_data"]
    )
    hsm_reversible_key_operations._client.generate_aes_key = MagicMock(
        return_value=True
    )
    hsm_reversible_key_operations._client.generate_secret_key = MagicMock(
        return_value=True
    )

    result = hsm_reversible_key_operations.encrypt(valid_organization_id, 1, iv, data)

    assert result == b"encrypted_data"
    hsm_reversible_key_operations._client.generate_aes_key.assert_called_once()
    hsm_reversible_key_operations._client.generate_secret_key.assert_called_once()
    assert hsm_reversible_key_operations._client.encrypt.call_count == 2


def test_hsm_reversible_key_operations_encrypt_should_raise_when_hsm_unreachable(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"1234567890123456"
    data = b"test_data"

    hsm_reversible_key_operations._client.encrypt = MagicMock(
        side_effect=ConnectionError("Connection failed")
    )

    with pytest.raises(ConnectionError):
        hsm_reversible_key_operations.encrypt(valid_organization_id, 1, iv, data)


def test_hsm_reversible_key_operations_encrypt_should_raise_when_hsm_error(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"1234567890123456"
    data = b"test_data"

    hsm_reversible_key_operations._client.encrypt = MagicMock(
        side_effect=HTTPError("HTTP error")
    )

    with pytest.raises(HTTPError):
        hsm_reversible_key_operations.encrypt(valid_organization_id, 1, iv, data)


def test_hsm_reversible_key_operations_decrypt_should_return_result(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"1234567890123456"
    data = b"encrypted_data"

    hsm_reversible_key_operations._client.decrypt = MagicMock(
        return_value=b"decrypted_data"
    )

    result = hsm_reversible_key_operations.decrypt(valid_organization_id, 1, iv, data)

    assert result == b"decrypted_data"
    hsm_reversible_key_operations._client.decrypt.assert_called_once()


def test_hsm_reversible_key_operations_decrypt_should_raise_when_hsm_unreachable(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"1234567890123456"
    data = b"encrypted_data"

    hsm_reversible_key_operations._client.decrypt = MagicMock(
        side_effect=ConnectionError("Connection failed")
    )

    with pytest.raises(ConnectionError):
        hsm_reversible_key_operations.decrypt(valid_organization_id, 1, iv, data)


def test_hsm_reversible_key_operations_decrypt_should_raise_when_hsm_error(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    iv = b"1234567890123456"
    data = b"encrypted_data"

    hsm_reversible_key_operations._client.decrypt = MagicMock(
        side_effect=HTTPError("HTTP error")
    )

    with pytest.raises(HTTPError):
        hsm_reversible_key_operations.decrypt(valid_organization_id, 1, iv, data)


def test_hsm_reversible_key_operations_destroy_should_call_client_for_both_labels(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    hsm_reversible_key_operations._client.destroy_if_present = MagicMock(
        return_value=True
    )

    result = hsm_reversible_key_operations.destroy(valid_organization_id, 1)

    assert result is True
    assert hsm_reversible_key_operations._client.destroy_if_present.call_count == 2
    # Verify it was called with both labels
    calls = hsm_reversible_key_operations._client.destroy_if_present.call_args_list
    labels = [call[0][0] for call in calls]
    assert f"oin-{valid_organization_id.value}-rp-v1-aes" in labels
    assert f"oin-{valid_organization_id.value}-rp-v1-hmac" in labels


def test_hsm_reversible_key_operations_destroy_should_raise_when_hsm_unreachable(
    hsm_reversible_key_operations: HsmReversibleKeyOperations,
    valid_organization_id: Oin,
) -> None:
    hsm_reversible_key_operations._client.destroy_if_present = MagicMock(
        side_effect=ConnectionError("Connection failed")
    )

    with pytest.raises(ConnectionError):
        hsm_reversible_key_operations.destroy(valid_organization_id, 1)
