import pytest

from app.models.personal_id import PersonalId, PersonalIdValidationError


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

    with pytest.raises(ValueError) as e:
        PersonalId.from_str("NL-bsn-950000012")

    assert "Invalid personal ID format" in str(e.value)


def test_invalid_country_code() -> None:
    with pytest.raises(ValueError) as e:
        PersonalId("NLD", "bsn", "950000012")
        assert "country_code must be a 2-letter ISO country code" in str(e.value)

    with pytest.raises(ValueError) as e:
        PersonalId("N1", "bsn", "950000012")
        assert "country_code must be a 2-letter ISO country code" in str(e.value)


def test_invalid_id_type() -> None:
    with pytest.raises(ValueError) as e:
        PersonalId("NL", "invalid", "950000012")
        assert "id_type must be one of: bsn" in str(e.value)


def test_from_dict() -> None:
    p = PersonalId.from_dict({"landCode": "NL", "type": "bsn", "value": "950000012"})
    assert p.country_code() == "NL"
    assert p.id_type() == "bsn"
    assert p.id_number() == "950000012"

    with pytest.raises(ValueError):
        PersonalId.from_dict(
            {"landCode": "NL", "type": "bsn", "incorrect_key": "950000012"}
        )


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


def test_parse_accepts_string_and_dict() -> None:
    expected = PersonalId("NL", "bsn", "950000012")

    assert PersonalId.parse("NL:bsn:950000012") == expected
    assert (
        PersonalId.parse({"landCode": "NL", "type": "bsn", "value": "950000012"})
        == expected
    )


@pytest.mark.parametrize("raw", ["NL:bsn", {"landCode": "NL", "type": "bsn"}])
def test_parse_rejects_malformed_input(raw: str | dict[str, str]) -> None:
    with pytest.raises(PersonalIdValidationError) as e:
        PersonalId.parse(raw)

    assert e.value.kind == "formaat"
