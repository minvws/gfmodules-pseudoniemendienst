import base64
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import gfmodules.logging as gflog
import pytest
from gfmodules.logging import DefaultEventCatalogue, LogEvent, LoggingStreams
from gfmodules.logging.testing import assert_catalogue_complete, capture_records
from jwcrypto import jwk

from app.config import ConfigOprf
from app.logging.events import Log
from app.models.oin import RecipientOrganizationOin
from app.models.requests import BlindRequest
from app.services.oprf.evaluators import HsmOprfEvaluator, LocalOprfEvaluator
from app.services.oprf.oprf_service import OprfEvaluationError, OprfService


def test_catalogue_defines_every_required_event() -> None:
    assert_catalogue_complete(Log, access_logs=False)


def test_emit_attaches_event_id_and_streams() -> None:
    logger = logging.getLogger("app.test_events")
    with capture_records("app.test_events") as records:
        gflog.emit(logger, Log.OPRF_EVAL_OK, "evaluated", fields={"doel_oin": "oin:x"})

    record = records.entries[-1].record
    assert record.event_id == Log.OPRF_EVAL_OK.event_id  # type: ignore[attr-defined]
    assert LoggingStreams.APP in record.stream  # type: ignore[attr-defined]
    assert LoggingStreams.SIEM in record.stream  # type: ignore[attr-defined]
    assert record.doel_oin == "oin:x"  # type: ignore[attr-defined]
    assert record.levelno == logging.INFO


@pytest.mark.parametrize(
    "event,expected_id,expected_level",
    [
        (Log.OPRF_EVAL_OK, "210400", logging.INFO),
        (Log.OPRF_EVAL_FAILED, "210402", logging.ERROR),
        (Log.OPRF_REFUSED_NO_ACTIVE_PUBKEY, "210403", logging.WARNING),
        (Log.HEALTH_UNHEALTHY, "270400", logging.ERROR),
        (Log.SYS_APP_STOPPED, "270402", logging.INFO),
        (Log.SYS_APP_CRASHED, "270402", logging.CRITICAL),
        (Log.SYS_DB_CONNECTION_FAILED, "270403", logging.ERROR),
        (Log.SYS_UNHANDLED_EXCEPTION, "270404", logging.ERROR),
        (Log.SYS_MISSING_CORRELATION_ID, "270407", logging.ERROR),
        (Log.SYS_HSM_UNREACHABLE, "270406", logging.CRITICAL),
    ],
)
def test_events_match_logging_spec(
    event: LogEvent, expected_id: str, expected_level: int
) -> None:
    assert event.event_id == expected_id
    assert LoggingStreams.APP in event.streams
    assert LoggingStreams.SIEM in event.streams

    logger = logging.getLogger("app.test_events_levels")
    with capture_records("app.test_events_levels") as records:
        gflog.emit(logger, event, "msg")

    assert records.entries[-1].record.levelno == expected_level


def test_sys_app_started_has_app_stream_only() -> None:
    # PRS-SYS-001: "stroom 3" is "-" in the spec, so no SIEM stream.
    assert Log.SYS_APP_STARTED.event_id == "270401"
    assert Log.SYS_APP_STARTED.streams == (LoggingStreams.APP,)


def test_the_started_event_keeps_the_shared_allow_list_and_adds_this_services_own() -> (
    None
):
    allowed = Log.SYS_APP_STARTED.fields[LoggingStreams.APP]

    assert set(DefaultEventCatalogue.SYS_APP_STARTED.fields[LoggingStreams.APP]) <= set(
        allowed
    )
    assert {"environment", "oauth_enabled", "pseudoniem_api_enabled"} <= set(allowed)


def test_emit_includes_exc_info() -> None:
    logger = logging.getLogger("app.test_events_exc")
    try:
        raise ValueError("boom")
    except ValueError as e:
        with capture_records("app.test_events_exc") as records:
            gflog.emit(logger, Log.OPRF_EVAL_FAILED, "fail", exc_info=e)

    assert records.entries[-1].record.exc_info is not None


@pytest.fixture(scope="module")
def pub_key() -> jwk.JWK:
    key = jwk.JWK.generate(kty="RSA", size=2048)
    return jwk.JWK.from_json(key.export_public())


def _blind_request() -> BlindRequest:
    return BlindRequest(
        encryptedPersonalId=base64.urlsafe_b64encode(b"not-a-valid-point").decode(),
        recipientOrganization=RecipientOrganizationOin("oin:00000099000000001000"),
        recipientScope="nvi",
    )


def test_eval_blind_invalid_input_raises_invalid_blinded_input(
    pub_key: jwk.JWK,
) -> None:
    service = OprfService(
        evaluator=LocalOprfEvaluator(
            base64.urlsafe_b64decode(OprfService.generate_server_key())
        ),
    )

    with pytest.raises(OprfEvaluationError) as exc:
        service.eval_blind(_blind_request(), pub_key, None)

    assert exc.value.error_type == "invalid_blinded_input"


def test_eval_blind_hsm_failure_raises_crypto_evaluation_failure(
    pub_key: jwk.JWK,
) -> None:
    hsm_key_version_service = MagicMock()
    hsm_key_version_service.get_active_or_create_version_numbers_by_organization_id.return_value = [
        1
    ]
    org_service = MagicMock()
    org_service.get_by_oin.return_value = SimpleNamespace(id=uuid4())
    service = OprfService(
        evaluator=HsmOprfEvaluator(
            hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
            hsm_key_version_service=hsm_key_version_service,
            org_service=org_service,
        )
    )

    with (
        patch(
            "app.services.oprf.evaluators.requests.post",
            side_effect=RuntimeError("HSM unreachable"),
        ),
        pytest.raises(OprfEvaluationError) as exc,
    ):
        service.eval_blind(_blind_request(), pub_key, None)

    assert exc.value.error_type == "crypto_evaluation_failure"
