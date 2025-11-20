import base64
import pytest
from Crypto.Random import get_random_bytes

from app.services.rid_service import RidService


AES_KEY_SIZE = 32

@pytest.fixture
def aes_key() -> bytes:
    return get_random_bytes(AES_KEY_SIZE)


@pytest.fixture
def rid_service(aes_key: bytes) -> RidService:
    return RidService(aes_key, aad=b"RID:v1")


def test_encrypt_decrypt_roundtrip(rid_service: RidService) -> None:
    rid = '{"usage":"irp","recipient_organization":"org1","recipient_scope":"nvi","personal_id":"123456789"}'

    token = rid_service.encrypt_rid(rid)
    decrypted = rid_service.decrypt_rid(token)

    assert decrypted == rid


def test_ciphertext_is_not_deterministic_for_same_rid(rid_service: RidService) -> None:
    rid = '{"usage":"irp","recipient_organization":"org1","recipient_scope":"nvi","personal_id":"123456789"}'

    token1 = rid_service.encrypt_rid(rid)
    token2 = rid_service.encrypt_rid(rid)
    assert token1 != token2


def test_tampering_ciphertext_fails(rid_service: RidService) -> None:
    rid = '{"usage":"irp","recipient_organization":"org1","recipient_scope":"nvi","personal_id":"123456789"}'

    token = rid_service.encrypt_rid(rid)

    data = bytearray(base64.urlsafe_b64decode(token))
    data[len(data) // 2] ^= 0x01
    tampered_token = base64.urlsafe_b64encode(bytes(data)).decode("utf-8")

    with pytest.raises(ValueError):
        rid_service.decrypt_rid(tampered_token)


def test_wrong_key_fails(aes_key: bytes) -> None:
    rid = '{"usage":"irp","recipient_organization":"org1","recipient_scope":"nvi","personal_id":"123456789"}'

    service1 = RidService(aes_key, aad=b"RID:v1")
    token = service1.encrypt_rid(rid)

    other_key = get_random_bytes(AES_KEY_SIZE)
    service2 = RidService(other_key, aad=b"RID:v1")

    with pytest.raises(ValueError):
        service2.decrypt_rid(token)


def test_wrong_aad_fails(aes_key: bytes) -> None:
    rid = '{"usage":"irb","recipient_organization":"org1","recipient_scope":"nvi","personal_id":"123456789"}'

    service_correct = RidService(aes_key, aad=b"RID:v1")
    token = service_correct.encrypt_rid(rid)

    service_wrong_aad = RidService(aes_key, aad=b"RID:v2")

    with pytest.raises(ValueError):
        service_wrong_aad.decrypt_rid(token)
