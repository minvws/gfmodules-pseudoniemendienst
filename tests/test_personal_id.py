from app.personal_id import PersonalId


def test_personal_id() -> None:
    p = PersonalId("NL", "bsn", "123456789")
    assert p.country_code() == "NL"
    assert p.id_type() == "bsn"
    assert p.id_number() == "123456789"
    assert p.as_str() == "NL:bsn:123456789"
    assert p.as_dict() == {
        "landCode": "NL",
        "type": "bsn",
        "value": "123456789",
    }

def test_from_string() -> None:
    p = PersonalId.from_str("NL:bsn:123456789")
    assert p.country_code() == "NL"
    assert p.id_type() == "bsn"
    assert p.id_number() == "123456789"

    # Test invalid format
    try:
        PersonalId.from_str("NL-bsn-123456789")
        assert False, "Expected ValueError for invalid format"
    except ValueError as e:
        assert str(e) == "Invalid personal ID format"

def test_invalid_country_code() -> None:
    try:
        PersonalId("NLD", "bsn", "123456789")
        assert False, "Expected ValueError for invalid country code"
    except ValueError as e:
        assert str(e) == "country_code must be a 2-letter ISO country code"

    try:
        PersonalId("N1", "bsn", "123456789")
        assert False, "Expected ValueError for invalid country code"
    except ValueError as e:
        assert str(e) == "country_code must be a 2-letter ISO country code"

def test_invalid_id_type() -> None:
    try:
        PersonalId("NL", "invalid", "123456789")
        assert False, "Expected ValueError for invalid id type"
    except ValueError as e:
        assert str(e) == "id_type must be one of: bsn"


def test_from_dict() -> None:
    p = PersonalId.from_dict({"landCode": "NL", "type": "bsn", "value": "123456789"})
    assert p.country_code() == "NL"
    assert p.id_type() == "bsn"
    assert p.id_number() == "123456789"

    try:
        PersonalId.from_dict({"landCode": "NL", "type": "bsn", "incorrect_key": "123456789"})
        assert False, "Expected KeyError for missing 'value' key"
    except ValueError:
        assert True

def test_equality() -> None:
    p1 = PersonalId("NL", "bsn", "123456789")
    p2 = PersonalId("NL", "bsn", "123456789")
    p3 = PersonalId("NL", "bsn", "987654321")
    assert p1 == p2
    assert p1 != p3
    assert p1 != "not a PersonalId"


