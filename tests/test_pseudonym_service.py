from app.personal_id import PersonalId
from app.services.pseudonym_service import PseudonymService


def test_pseudonym_service_exchange() -> None:
    svc = PseudonymService(b"super_secret_hmac_key_for_testing_purposes_only", b"16byteslongkey!!")
    pseudonym = svc.exchange_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert isinstance(pseudonym, str)
    assert len(pseudonym) == 44
    assert pseudonym == "KEBcYemserL3Ku6ob-xjxBY3GWUcffkaCzKsJIJl3qg="

    # Consistency check
    pseudonym2 = svc.exchange_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert pseudonym == pseudonym2

    # Different input should yield different pseudonym
    pseudonym3 = svc.exchange_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:54321",
        recipient_scope="nvi"
    )
    assert pseudonym != pseudonym3

    # Different HMAC key should yield different pseudonym
    svc = PseudonymService(b"another_key_will_hmac_differently", b"16byteslongkey!!")
    pseudonym4 = svc.exchange_irreversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert pseudonym4 != pseudonym


def test_pseudonym_service_reversible() -> None:
    svc = PseudonymService(b"super_secret_hmac_key_for_testing_purposes_only", b"16byteslongkey!!")
    pseudonym = svc.exchange_reversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert isinstance(pseudonym, str)
    assert len(pseudonym) > 0
    assert pseudonym.find("|") == -1  # Should be encoded

    decoded = svc.decode_reversible_pseudonym(pseudonym)
    assert decoded['personal_id'].id_number() == "12345678901"   # type: ignore
    assert decoded['recipient_organization'] == "ura:12345"
    assert decoded['recipient_scope'] == "nvi"

    # Consistency check
    pseudonym2 = svc.exchange_reversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    # Encrypted pseudonym should be different due to random IV
    assert pseudonym != pseudonym2
    # But the result should be decodable to the same
    decoded2 = svc.decode_reversible_pseudonym(pseudonym2)
    assert decoded == decoded2

    # Different input should yield different pseudonym
    pseudonym3 = svc.exchange_reversible_pseudonym(
        personal_id=PersonalId("NL", "bsn", "12345678901"),
        recipient_organization="ura:54321",
        recipient_scope="nvi"
    )
    assert pseudonym != pseudonym3



