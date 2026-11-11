import pytest

from app.models.oin import Oin, RecipientOrganizationOin


# Test cases using fixtures
def test_oin_value_should_match_input(valid_organization_id: Oin) -> None:
    assert valid_organization_id.value == "00000099000000002000"


def test_oin_prefix_should_be_8_digits(valid_organization_id: Oin) -> None:
    assert valid_organization_id.prefix == "00000099"
    assert len(valid_organization_id.prefix) == 8


def test_oin_number_should_be_after_prefix(valid_organization_id: Oin) -> None:
    assert valid_organization_id.number == "000000002000"


def test_oin_mainnumber_should_be_correct(valid_organization_id: Oin) -> None:
    # For "00000099000000002000" (8 + 12)
    # prefix = "00000099", number = "000000002000"
    # The number ends with "000", so suffix = "000"
    # mainnumber = number without suffix = "000000002"
    assert valid_organization_id.mainnumber == "000000002"
    assert valid_organization_id.suffix == "000"


def test_oin_str_should_return_value(valid_organization_id: Oin) -> None:
    assert str(valid_organization_id) == "00000099000000002000"


def test_oin_equality_with_same_value(valid_organization_id: Oin) -> None:
    oin2 = Oin("00000099000000002000")
    assert valid_organization_id == oin2
    assert valid_organization_id == "00000099000000002000"


def test_oin_equality_with_different_value(
    valid_organization_id: Oin, valid_organization_id_2: Oin
) -> None:
    assert valid_organization_id != valid_organization_id_2
    assert valid_organization_id != "00000099000000003000"


def test_oin_hashing(valid_organization_id: Oin) -> None:
    oin2 = Oin("00000099000000002000")
    assert hash(valid_organization_id) == hash(oin2)


# Test cases for 9-character mainnumber
def test_oin_with_9_char_mainnumber() -> None:
    # 8 digit prefix + 9 alphanumeric + 3 zeros = 20 characters
    oin = Oin("00000099123456789000")
    assert oin.prefix == "00000099"
    assert oin.number == "123456789000"
    assert oin.mainnumber == "123456789"
    assert oin.suffix == "000"


# Error cases
def test_oin_should_raise_when_wrong_length() -> None:
    with pytest.raises(ValueError, match="Expected 20 characters"):
        Oin("123")


def test_oin_should_raise_when_invalid_format() -> None:
    with pytest.raises(ValueError, match="Invalid OIN"):
        Oin("0000009900000000100X")


def test_oin_should_raise_when_negative_integer() -> None:
    with pytest.raises(ValueError, match="must be a positive integer"):
        Oin(-123)


def test_oin_should_raise_when_wrong_type() -> None:
    with pytest.raises(ValueError, match="must be a string or integer"):
        Oin([1, 2, 3])


# RecipientOrganizationOin tests
def test_recipient_organization_oin_should_create_with_prefix() -> None:
    oin = RecipientOrganizationOin("oin:00000099000000001000")
    assert oin.value == "00000099000000001000"
    assert str(oin) == "oin:00000099000000001000"


def test_recipient_organization_oin_should_create_without_prefix() -> None:
    oin = RecipientOrganizationOin("00000099000000001000")
    assert oin.value == "00000099000000001000"
    assert str(oin) == "oin:00000099000000001000"


def test_recipient_organization_oin_should_raise_when_invalid_format() -> None:
    # The error comes from the parent Oin class when the value is invalid
    with pytest.raises(ValueError, match="Expected 20 characters"):
        RecipientOrganizationOin("invalid")


def test_recipient_organization_oin_should_create_from_oin(
    valid_organization_id: Oin,
) -> None:
    recipient_oin = RecipientOrganizationOin(valid_organization_id)
    assert recipient_oin.value == valid_organization_id.value
    assert str(recipient_oin) == f"oin:{valid_organization_id.value}"
