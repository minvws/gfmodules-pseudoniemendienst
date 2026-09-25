import pytest

from app.personal_id import PersonalId, PersonalIdValidationError


def test_personal_id() -> None:
    p = PersonalId("NL", "bsn", "950000012")
    assert p.country_code() == "NL"
    assert p.id_type() == "bsn"
    assert p.id_number() == "950000012"
    assert p.as_str() == "NL:bsn:950000012"
    assert p.as_dict() == {
        "landCode": "NL",
        "type": "bsn",
        "value": "950000012",
    }


def test_from_string() -> None:
    p = PersonalId.from_str("NL:bsn:950000012")
    assert p.country_code() == "NL"
    assert p.id_type() == "bsn"
    assert p.id_number() == "950000012"

    # Test invalid format
    try:
        PersonalId.from_str("NL-bsn-950000012")
        assert False, "Expected ValueError for invalid format"
    except ValueError as e:
        assert str(e) == "Invalid personal ID format"


def test_invalid_country_code() -> None:
    try:
        PersonalId("NLD", "bsn", "950000012")
        assert False, "Expected ValueError for invalid country code"
    except ValueError as e:
        assert str(e) == "country_code must be a 2-letter ISO country code"

    try:
        PersonalId("N1", "bsn", "950000012")
        assert False, "Expected ValueError for invalid country code"
    except ValueError as e:
        assert str(e) == "country_code must be a 2-letter ISO country code"


def test_invalid_id_type() -> None:
    try:
        PersonalId("NL", "invalid", "950000012")
        assert False, "Expected ValueError for invalid id type"
    except ValueError as e:
        assert str(e) == "id_type must be one of: bsn"


def test_from_dict() -> None:
    p = PersonalId.from_dict({"landCode": "NL", "type": "bsn", "value": "950000012"})
    assert p.country_code() == "NL"
    assert p.id_type() == "bsn"
    assert p.id_number() == "950000012"

    try:
        PersonalId.from_dict(
            {"landCode": "NL", "type": "bsn", "incorrect_key": "950000012"}
        )
        assert False, "Expected KeyError for missing 'value' key"
    except ValueError:
        assert True


def test_equality() -> None:
    p1 = PersonalId("NL", "bsn", "950000012")
    p2 = PersonalId("NL", "bsn", "950000012")
    p3 = PersonalId("NL", "bsn", "950000024")
    assert p1 == p2
    assert p1 != p3
    assert p1 != "not a PersonalId"


@pytest.mark.parametrize(
    "value,kind",
    [
        ("95000001a", "formaat"),
        ("9500 0012", "formaat"),
        ("95000001", "lengte"),
        ("9500000123", "lengte"),
        ("950000013", "elfproef"),
        ("123456789", "elfproef"),
    ],
)
def test_bsn_validation_reports_the_kind_of_failure(value: str, kind: str) -> None:
    with pytest.raises(PersonalIdValidationError) as e:
        PersonalId("NL", "bsn", value)

    assert e.value.kind == kind
    assert value not in str(e.value)


@pytest.mark.parametrize("value", ["950000012", "950000024", "999991772", "111222333"])
def test_bsn_that_passes_the_elfproef_is_accepted(value: str) -> None:
    assert PersonalId("NL", "bsn", value).id_number() == value


def test_format_failures_report_formaat() -> None:
    with pytest.raises(PersonalIdValidationError) as e:
        PersonalId.from_str("NL-bsn-950000012")
    assert e.value.kind == "formaat"

    with pytest.raises(PersonalIdValidationError) as e:
        PersonalId.from_dict({"landCode": "NL", "type": "bsn"})
    assert e.value.kind == "formaat"

    with pytest.raises(PersonalIdValidationError) as e:
        PersonalId("NL", "passport", "950000012")
    assert e.value.kind == "formaat"
