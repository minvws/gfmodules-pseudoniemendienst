import base64
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from jwcrypto import jwk

from app.config import ConfigOprf
from app.logging.events import (
    HEALTH_UNHEALTHY,
    OPRF_EVAL_FAILED,
    OPRF_EVAL_OK,
    OPRF_REFUSED_NO_ACTIVE_PUBKEY,
    SYS_APP_CRASHED,
    SYS_APP_STARTED,
    SYS_APP_STOPPED,
    SYS_DB_CONNECTION_FAILED,
    SYS_HSM_UNREACHABLE,
    SYS_UNHANDLED_EXCEPTION,
    PRSEvent,
    log_event,
)
from app.logging.filters import LoggingStreams
from app.models.oin import RecipientOrganizationOin
from app.models.requests import BlindRequest
from app.services.oprf.oprf_service import OprfEvaluationError, OprfService


def test_log_event_attaches_event_id_and_streams(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger("test.events")
    logger.setLevel(logging.DEBUG)
    with caplog.at_level(logging.DEBUG, logger="test.events"):
        log_event(logger, OPRF_EVAL_OK, "evaluated", doel_oin="oin:x")

    record = caplog.records[-1]
    assert record.event_id == OPRF_EVAL_OK.event_id  # type: ignore[attr-defined]
    assert LoggingStreams.APP in record.stream  # type: ignore[attr-defined]
    assert LoggingStreams.SIEM in record.stream  # type: ignore[attr-defined]
    assert record.doel_oin == "oin:x"  # type: ignore[attr-defined]
    assert record.levelno == logging.INFO


@pytest.mark.parametrize(
    "event,expected_id,expected_level",
    [
        (OPRF_EVAL_OK, "210400", logging.INFO),
        (OPRF_EVAL_FAILED, "210402", logging.ERROR),
        (OPRF_REFUSED_NO_ACTIVE_PUBKEY, "210403", logging.WARNING),
        (HEALTH_UNHEALTHY, "270400", logging.ERROR),
        (SYS_APP_STOPPED, "270402", logging.INFO),
        (SYS_APP_CRASHED, "270402", logging.CRITICAL),
        (SYS_DB_CONNECTION_FAILED, "270403", logging.ERROR),
        (SYS_UNHANDLED_EXCEPTION, "270404", logging.ERROR),
        (SYS_HSM_UNREACHABLE, "270406", logging.CRITICAL),
    ],
)
def test_events_match_logging_spec(
    caplog: pytest.LogCaptureFixture,
    event: PRSEvent,
    expected_id: str,
    expected_level: int,
) -> None:
    assert event.event_id == expected_id
    assert LoggingStreams.APP in event.streams
    assert LoggingStreams.SIEM in event.streams

    logger = logging.getLogger("test.events_levels")
    logger.setLevel(logging.DEBUG)
    with caplog.at_level(logging.DEBUG, logger="test.events_levels"):
        log_event(logger, event, "msg")
    assert caplog.records[-1].levelno == expected_level


def test_sys_app_started_has_app_stream_only() -> None:
    # PRS-SYS-001: "stroom 3" is "-" in the spec, so no SIEM stream.
    assert SYS_APP_STARTED.event_id == "270401"
    assert SYS_APP_STARTED.streams == (LoggingStreams.APP,)


def test_log_event_includes_exc_info(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("test.events_exc")
    logger.setLevel(logging.DEBUG)
    try:
        raise ValueError("boom")
    except ValueError as e:
        with caplog.at_level(logging.DEBUG, logger="test.events_exc"):
            log_event(logger, OPRF_EVAL_FAILED, "fail", exc_info=e)

    assert caplog.records[-1].exc_info is not None


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
    service = OprfService(server_key=OprfService.generate_server_key())

    with pytest.raises(OprfEvaluationError) as exc:
        service.eval_blind(_blind_request(), pub_key, None)

    assert exc.value.error_type == "invalid_blinded_input"


def test_eval_blind_without_active_versions_raises_secret_version_destroyed(
    pub_key: jwk.JWK,
) -> None:
    hsm_key_version_service = MagicMock()
    hsm_key_version_service.get_active_versions.return_value = []
    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=hsm_key_version_service,
    )

    with pytest.raises(OprfEvaluationError) as exc:
        service.eval_blind(_blind_request(), pub_key, None)

    assert exc.value.error_type == "secret_version_destroyed"


def test_eval_blind_hsm_failure_raises_crypto_evaluation_failure(
    pub_key: jwk.JWK,
) -> None:
    hsm_key_version_service = MagicMock()
    hsm_key_version_service.get_active_versions.return_value = [
        SimpleNamespace(version=1)
    ]
    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=hsm_key_version_service,
    )

    with (
        patch(
            "app.services.oprf.oprf_service.requests.post",
            side_effect=RuntimeError("HSM unreachable"),
        ),
        pytest.raises(OprfEvaluationError) as exc,
    ):
        service.eval_blind(_blind_request(), pub_key, None)

    assert exc.value.error_type == "crypto_evaluation_failure"
