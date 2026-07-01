from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_openapi_includes_hsm_key_version_request_descriptions(app: FastAPI) -> None:
    schema = app.openapi()

    hsm_schema = schema["components"]["schemas"]["HsmKeyVersionRequest"]
    hsm_update_schema = schema["components"]["schemas"]["HsmKeyVersionUpdateRequest"]
    assert "from_dt is validated against the current UTC timestamp" in str(
        hsm_schema["x-temporal-constraints"]
    )
    assert (
        "timezone offset" in hsm_schema["properties"]["from_dt"]["description"].lower()
    )
    assert (
        "timezone offset"
        in hsm_update_schema["properties"]["until_dt"]["description"].lower()
    )
    assert "x-supported-timezones" in hsm_schema
    assert (
        "until_dt must be at or after from_dt (or current UTC when from_dt is "
        "omitted)" in str(hsm_schema["x-temporal-constraints"])
    )
    assert hsm_schema["properties"]["from_dt"]["description"] != ""
    assert hsm_schema["properties"]["until_dt"]["description"] != ""
    assert hsm_update_schema["properties"]["until_dt"]["description"] != ""


def test_openapi_includes_hsm_key_version_examples(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    payload = response.json()
    hsm_schema = payload["components"]["schemas"]["HsmKeyVersionRequest"]
    hsm_update_schema = payload["components"]["schemas"]["HsmKeyVersionUpdateRequest"]

    assert "x-temporal-constraints" in hsm_schema
    assert hsm_schema["x-temporal-constraints"] == [
        "from_dt is validated against the current UTC timestamp",
        "until_dt must be at or after from_dt (or current UTC when from_dt is omitted)",
        "timezone offset is required for from_dt and until_dt (RFC3339 date-time format)",
    ]
    assert "x-supported-timezones" in hsm_schema
    assert hsm_update_schema["x-temporal-constraints"] == [
        "timezone offset is required for until_dt (RFC3339 date-time format)",
    ]
    assert hsm_schema["properties"]["from_dt"]["description"] is not None
    assert hsm_update_schema["properties"]["until_dt"]["description"] is not None
