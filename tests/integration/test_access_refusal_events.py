from gfmodules.logging.testing import capture_records
from starlette.testclient import TestClient

from app.logging.events import Log
from app.models.oin import Oin

OPRF_BODY = {
    "encryptedPersonalId": "Zm9v",
    "recipientOrganization": "oin:00000099000000001000",
    "recipientScope": "nvi",
}


def test_requests_refused_before_the_exchange_are_logged(
    client: TestClient,
    valid_headers: dict[str, str],
    valid_organization_id: Oin,
    valid_client_organization_id: Oin,
) -> None:
    rejected_acting_organization = "not-an-organization-identifier"
    refusals = [
        {**valid_headers, "x-gf-act-sub": rejected_acting_organization},
        {**valid_headers, "x-gf-audience": "nvi.service"},
        {**valid_headers, "x-gf-scope": "prs:administration"},
    ]

    with capture_records("app") as captured:
        statuses = [
            client.post("/oprf/eval", json=OPRF_BODY, headers=headers).status_code
            for headers in refusals
        ]

    assert statuses == [403, 403, 403]
    (invalid_headers,) = captured.for_event(Log.MISSING_AUTHORIZATION_HEADER)
    assert invalid_headers.message["error_reason"] == "x-gf-act-sub: value_error"
    assert rejected_acting_organization not in str(invalid_headers.message)
    denied = [
        (
            entry.message["acting_organization_identifier"],
            entry.message["represented_organization_identifier"],
            entry.message.get("requested_operation"),
            entry.message["error_reason"],
        )
        for entry in captured.for_event(Log.AUTHORIZATION_DENIED)
    ]
    acting, represented = (
        valid_client_organization_id.value,
        valid_organization_id.value,
    )
    assert denied == [
        (acting, represented, None, "audience_not_accepted"),
        (acting, represented, "prs:oprf-pseudonym", "scope_missing"),
    ]
