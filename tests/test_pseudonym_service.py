

from app.services.pseudonym_service import PseudonymService


def test_pseudonym_service_exchange() -> None:
    svc = PseudonymService(b"super_secret_hmac_key_for_testing_purposes_only")
    pseudonym = svc.exchange_irreversible_pseudonym(
        personal_id="12345678901",
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert isinstance(pseudonym, str)
    assert len(pseudonym) == 44
    assert pseudonym == "bf9zAwUtXTDnPwy-9JT6VKU1ZUdAcgfv1ZnGc9E1pfE="

    # Consistency check
    pseudonym2 = svc.exchange_irreversible_pseudonym(
        personal_id="12345678901",
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert pseudonym == pseudonym2

    # Different input should yield different pseudonym
    pseudonym3 = svc.exchange_irreversible_pseudonym(
        personal_id="12345678901",
        recipient_organization="ura:54321",
        recipient_scope="nvi"
    )
    assert pseudonym != pseudonym3

    # Different HMAC key should yield different pseudonym
    svc = PseudonymService(b"another_key_will_hmac_differently")
    pseudonym4 = svc.exchange_irreversible_pseudonym(
        personal_id="12345678901",
        recipient_organization="ura:12345",
        recipient_scope="nvi"
    )
    assert pseudonym4 != pseudonym
