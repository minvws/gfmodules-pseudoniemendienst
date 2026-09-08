import pytest

from app.db.entities.organization import Organization
from app.models.oin import Oin
from app.services.exchange_authorization import (
    ExchangeNotAuthorized,
    assert_may_provide_personal_id,
    assert_may_receive_reversible_pseudonym,
)


def _org(max_rid_usage: str, may_provide_personal_id: bool = False) -> Organization:
    return Organization(
        oin=Oin("00000099000000001000"),
        name="org",
        max_rid_usage=max_rid_usage,
        may_provide_personal_id=may_provide_personal_id,
        may_receive_personal_id=False,
    )


def test_sender_with_flag_may_provide_personal_id() -> None:
    assert_may_provide_personal_id(_org("irp", may_provide_personal_id=True))


def test_sender_without_flag_may_not_provide_personal_id() -> None:
    with pytest.raises(ExchangeNotAuthorized) as e:
        assert_may_provide_personal_id(_org("bsn", may_provide_personal_id=False))
    assert e.value.reason == "sender_may_not_provide_personal_id"


@pytest.mark.parametrize("max_rid_usage", ["rp", "bsn"])
def test_recipient_with_reversible_usage_or_higher_may_receive(
    max_rid_usage: str,
) -> None:
    assert_may_receive_reversible_pseudonym(_org(max_rid_usage))


@pytest.mark.parametrize("max_rid_usage", ["irp", "", "unknown"])
def test_recipient_below_reversible_usage_may_not_receive(max_rid_usage: str) -> None:
    with pytest.raises(ExchangeNotAuthorized) as e:
        assert_may_receive_reversible_pseudonym(_org(max_rid_usage))
    assert e.value.reason == "recipient_may_not_receive_reversible_pseudonym"
