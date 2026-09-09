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


def test_irp_is_deterministic(
    service: PseudonymService, sample_args: SampleArgs
) -> None:
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


def test_pseudonym_service_exchange() -> None:
    svc = PseudonymService(b"super_secret_hmac_key_for_testing_purposes_only")
    pseudonym = svc.generate_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi",
    )
    assert isinstance(pseudonym, str)
    assert len(pseudonym) == 44
    assert pseudonym == "suEcDbvslyhp6UwexSCUuySngPGXsF5kNF-R2izFnzA="

    # Consistency check
    pseudonym2 = svc.generate_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi",
    )
    assert pseudonym == pseudonym2

    # Different input should yield different pseudonym
    pseudonym3 = svc.generate_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:54321",
        recipient_scope="nvi",
    )
    assert pseudonym != pseudonym3

    # Different HMAC key should yield different pseudonym
    svc = PseudonymService(b"another_key_will_hmac_differently")
    pseudonym4 = svc.generate_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi",
    )
    assert pseudonym4 != pseudonym
