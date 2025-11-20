import base64
import os
from typing import TypedDict

import pytest

from app.personal_id import PersonalId
from app.services.pseudonym_service import PseudonymService


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def service(master_key: bytes) -> PseudonymService:
    return PseudonymService(master_key)


class SampleArgs(TypedDict):
    personal_id: PersonalId
    recipient_organization: str
    recipient_scope: str

@pytest.fixture
def sample_args() -> SampleArgs:
    return {
        "personal_id": PersonalId.from_str("nl:bsn:123456789"),
        "recipient_organization": "org1",
        "recipient_scope": "nvi",
    }


def test_irp_is_deterministic(service: PseudonymService, sample_args: SampleArgs) -> None:
    p1 = service.generate_irreversible_pseudonym(**sample_args)
    p2 = service.generate_irreversible_pseudonym(**sample_args)
    assert p1 == p2


def test_irp_changes_with_personal_id(service: PseudonymService) -> None:
    args1: SampleArgs = {
        "personal_id": PersonalId.from_str("nl:bsn:123456789"),
        "recipient_organization": "org1",
        "recipient_scope": "nvi",
    }
    args2: SampleArgs = {
        "personal_id": PersonalId.from_str("nl:bsn:987654321"),
        "recipient_organization": "org1",
        "recipient_scope": "nvi",
    }

    p1 = service.generate_irreversible_pseudonym(**args1)
    p2 = service.generate_irreversible_pseudonym(**args2)
    assert p1 != p2


def test_irp_changes_with_org_or_scope(service: PseudonymService) -> None:
    pid = PersonalId.from_str("nl:bsn:123456789")

    p_org1 = service.generate_irreversible_pseudonym(pid, "org1", "nvi")
    p_org2 = service.generate_irreversible_pseudonym(pid, "org2", "nvi")
    p_scope = service.generate_irreversible_pseudonym(pid, "org1", "prs")

    assert p_org1 != p_org2
    assert p_org1 != p_scope


def test_rp_is_deterministic(service: PseudonymService, sample_args: SampleArgs) -> None:
    p1 = service.generate_reversible_pseudonym(**sample_args)
    p2 = service.generate_reversible_pseudonym(**sample_args)
    assert p1 == p2


def test_rp_changes_with_personal_id(service: PseudonymService) -> None:
    args1: SampleArgs = {
        "personal_id": PersonalId.from_str("nl:bsn:123456789"),
        "recipient_organization": "org1",
        "recipient_scope": "nvi",
    }
    args2: SampleArgs = {
        "personal_id": PersonalId.from_str("nl:bsn:987654321"),
        "recipient_organization": "org1",
        "recipient_scope": "nvi",
    }

    p1 = service.generate_reversible_pseudonym(**args1)
    p2 = service.generate_reversible_pseudonym(**args2)
    assert p1 != p2


def test_rp_changes_with_org_or_scope(service: PseudonymService) -> None:
    pid = PersonalId.from_str("nl:bsn:123456789")

    p_org1 = service.generate_reversible_pseudonym(pid, "org1", "nvi")
    p_org2 = service.generate_reversible_pseudonym(pid, "org2", "nvi")
    p_scope = service.generate_reversible_pseudonym(pid, "org1", "prs")

    assert p_org1 != p_org2
    assert p_org1 != p_scope


def test_rp_roundtrip(service: PseudonymService, sample_args: SampleArgs) -> None:
    rp = service.generate_reversible_pseudonym(**sample_args)

    decoded = service.decrypt_reversible_pseudonym(
        rp, sample_args["recipient_organization"]
    )

    assert isinstance(decoded["personal_id"], PersonalId)
    assert decoded["personal_id"].as_str() == sample_args["personal_id"].as_str()
    assert decoded["recipient_organization"] == sample_args["recipient_organization"]
    assert decoded["recipient_scope"] == sample_args["recipient_scope"]


def test_rp_decrypt_with_wrong_org_fails(service: PseudonymService, sample_args: SampleArgs) -> None:
    rp = service.generate_reversible_pseudonym(**sample_args)

    # Decrypting with another org should fail (wrong key)
    with pytest.raises(ValueError):
        service.decrypt_reversible_pseudonym(rp, "OTHER_ORG")


def test_rp_tampering_fails(service: PseudonymService, sample_args: SampleArgs) -> None:
    rp = service.generate_reversible_pseudonym(**sample_args)

    raw = bytearray(base64.urlsafe_b64decode(rp))
    # Flip a bit somewhere in the payload
    raw[len(raw) // 2] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(raw)).decode("utf-8")

    with pytest.raises(ValueError):
        service.decrypt_reversible_pseudonym(
            tampered, sample_args["recipient_organization"]
        )



def test_pseudonym_service_exchange() -> None:
    svc = PseudonymService(b"super_secret_hmac_key_for_testing_purposes_only")
    pseudonym = svc.generate_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert isinstance(pseudonym, str)
    assert len(pseudonym) == 44
    assert pseudonym == "suEcDbvslyhp6UwexSCUuySngPGXsF5kNF-R2izFnzA="

    # Consistency check
    pseudonym2 = svc.generate_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert pseudonym == pseudonym2

    # Different input should yield different pseudonym
    pseudonym3 = svc.generate_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:54321",
        recipient_scope="nvi"
    )
    assert pseudonym != pseudonym3

    # Different HMAC key should yield different pseudonym
    svc = PseudonymService(b"another_key_will_hmac_differently")
    pseudonym4 = svc.generate_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert pseudonym4 != pseudonym


def test_pseudonym_service_reversible() -> None:
    svc = PseudonymService(b"super_secret_hmac_key_for_testing_purposes_only")
    pseudonym = svc.generate_reversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert isinstance(pseudonym, str)
    assert len(pseudonym) > 0
    assert pseudonym.find("|") == -1  # Should be encoded

    decoded = svc.decrypt_reversible_pseudonym(pseudonym, "ura:12345")
    assert decoded['personal_id'].id_number() == "12345678901"   # type: ignore
    assert decoded['recipient_organization'] == "ura:12345"
    assert decoded['recipient_scope'] == "nvi"

    try:
        decoded = svc.decrypt_reversible_pseudonym(pseudonym, "ura:99999")
        assert False, "Expected ValueError for decoding with wrong organization"
    except ValueError as e:
        assert str(e).startswith("Failed to decode reversible pseudonym")


    # Consistency check
    pseudonym2 = svc.generate_reversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    # Every time a pseudonym is created it should result in the same output
    assert pseudonym == pseudonym2

    # Different input should yield different pseudonym
    pseudonym3 = svc.generate_reversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:54321",
        recipient_scope="nvi"
    )
    assert pseudonym != pseudonym3

