import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from jwcrypto import jwk

from app.db.db import Database
from app.db.session import DbSession
from app.models.oin import RecipientOrganizationOin
from app.models.requests import BlindRequest
from app.services.hsm.client import HsmKeyNotFound
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.oprf.evaluators import (
    HsmOprfEvaluator,
    LocalOprfEvaluator,
    OprfHsmKeyLabel,
)
from app.services.oprf.oprf_service import OprfService
from tests.conftest import blinded_input, hsm_client
from tests.services.test_hsm_key_version_service import (
    TEST_OIN,
    TEST_OIN_78000,
    TEST_OIN_79000,
    TEST_OIN_WITH_PREFIX,
    add_hsm_key_version,
)


def test_eval_via_hsm_returns_entry_per_active_version(
    hsm_key_version_service: HsmKeyVersionService,
    database: Database,
    db_session: DbSession,
) -> None:
    now = datetime.now(timezone.utc)
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN_78000,
        version=2,
        from_dt=now - timedelta(days=2),
    )
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN_78000,
        version=7,
        from_dt=now - timedelta(days=1),
    )
    # a removed version must be ignored
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN_78000,
        version=9,
        from_dt=now - timedelta(days=1),
        removed_at=now,
    )

    evaluator = HsmOprfEvaluator(hsm_client(), hsm_key_version_service)

    with (
        patch.object(evaluator._client, "generate_oprf_key") as generate_key,
        patch.object(
            evaluator._client, "oprf_evaluate", return_value=b"evaluated"
        ) as evaluate_label,
    ):
        result = evaluator.evaluate(TEST_OIN_78000, b"blinded")

    assert result == {1: b"evaluated", 2: b"evaluated", 7: b"evaluated"}

    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        ("oin-00000000012345678000-oprf-v1", b"blinded"),
        ("oin-00000000012345678000-oprf-v2", b"blinded"),
        ("oin-00000000012345678000-oprf-v7", b"blinded"),
    ]

    # Existing keys are used directly, without a lookup or a create.
    assert evaluate_label.call_count == 3
    assert generate_key.call_count == 0


def test_eval_generates_keys_if_needed(
    database: Database,
    db_session: DbSession,
) -> None:
    now = datetime.now(timezone.utc)
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN_79000,
        version=2,
        from_dt=now - timedelta(days=2),
    )

    evaluator = HsmOprfEvaluator(
        hsm_client(),
        HsmKeyVersionService(database),
    )

    created: set[str] = set()

    def fake_evaluate(label: str, blinded: bytes) -> bytes:
        if label not in created:
            raise HsmKeyNotFound(f"No such key: {label}")
        return b"evaluated"

    def fake_generate(label: str) -> bool:
        created.add(label)
        return True

    with (
        patch.object(
            evaluator._client, "generate_oprf_key", side_effect=fake_generate
        ) as generate_key,
        patch.object(
            evaluator._client, "oprf_evaluate", side_effect=fake_evaluate
        ) as evaluate_label,
    ):
        result = evaluator.evaluate(TEST_OIN_79000, b"blinded")

    assert result == {1: b"evaluated", 2: b"evaluated"}

    assert [str(c.args[0]) for c in generate_key.call_args_list] == [
        "oin-00000000012345679000-oprf-v1",
        "oin-00000000012345679000-oprf-v2",
    ]

    # Evaluate first; only a missing key triggers a create and one retry.
    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        ("oin-00000000012345679000-oprf-v1", b"blinded"),
        ("oin-00000000012345679000-oprf-v1", b"blinded"),
        ("oin-00000000012345679000-oprf-v2", b"blinded"),
        ("oin-00000000012345679000-oprf-v2", b"blinded"),
    ]


def test_eval_blind_subject_is_latest_with_extra_versions(
    database: Database,
    db_session: DbSession,
) -> None:
    from jwcrypto import jwe as jwelib
    from jwcrypto import jwk

    from app.models.requests import BlindRequest

    now = datetime.now(timezone.utc)
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN_78000,
        version=2,
        from_dt=now - timedelta(days=2),
    )
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN_78000,
        version=7,
        from_dt=now - timedelta(days=1),
    )

    evaluator = HsmOprfEvaluator(
        hsm_client(),
        HsmKeyVersionService(database),
    )
    service = OprfService(evaluator)

    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    # type: ignore[type-arg]
    def fake_post(method: str, url: str, json: dict, **kwargs: object) -> MagicMock:
        # Return slot info when asked
        if url == "https://hsm.local/hsm/softhsm/SoftHSMLabel":
            resp = MagicMock()
            resp.json.return_value = {
                "objects": ["foobar"],
            }
            return resp

        version = json["label"].rsplit("v", 1)[-1]
        resp = MagicMock()
        resp.json.return_value = {
            "result": base64.b64encode(f"eval-v{version}".encode()).decode()
        }
        return resp

    req = BlindRequest(
        encryptedPersonalId=blinded_input(),
        recipientOrganization=RecipientOrganizationOin("oin:00000000012345678000"),
        recipientScope="scope",
    )

    with patch("requests.Session.request", side_effect=fake_post):
        result = service.eval_blind(req, pub)

    assert result.key_versions == (1, 2, 7)

    token = jwelib.JWE()
    token.deserialize(result.jwe)
    token.decrypt(key)
    body = json.loads(token.payload.decode("utf-8"))

    # The subject holds the latest version (v7) in the original format.
    assert (
        body["subject"]
        == "pseudonym:eval:" + base64.urlsafe_b64encode(b"eval-v7").decode()
    )
    # Older versions are carried separately so newer clients can detect them.
    assert body["extraVersions"] == {
        "1": base64.urlsafe_b64encode(b"eval-v1").decode(),
        "2": base64.urlsafe_b64encode(b"eval-v2").decode(),
    }
    assert "extra_versions" not in body


def test_eval_blind_jwe_contains_only_versions_active_at_date(
    database: Database,
    db_session: DbSession,
) -> None:
    from jwcrypto import jwe as jwelib
    from jwcrypto import jwk

    from app.models.requests import BlindRequest

    now = datetime.now(timezone.utc)
    # expired: ended yesterday -> excluded
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN,
        version=2,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )
    # active: started, no end date
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN,
        version=3,
        from_dt=now - timedelta(days=5),
        until_dt=None,
    )
    # active: within window
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN,
        version=5,
        from_dt=now - timedelta(days=2),
        until_dt=now + timedelta(days=2),
    )
    # future: not started yet -> excluded
    add_hsm_key_version(
        db_session,
        external_id=TEST_OIN,
        version=8,
        from_dt=now + timedelta(days=1),
        until_dt=None,
    )

    evaluator = HsmOprfEvaluator(
        hsm_client(),
        HsmKeyVersionService(database),
    )
    service = OprfService(evaluator)

    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    # type: ignore[type-arg]
    def fake_post(method: str, url: str, json: dict, **kwargs: object) -> MagicMock:
        # Return slot info when asked
        if url == "https://hsm.local/hsm/softhsm/SoftHSMLabel":
            resp = MagicMock()
            resp.json.return_value = {
                "objects": ["foobar"],
            }
            return resp

        version = json["label"].rsplit("v", 1)[-1]
        resp = MagicMock()
        resp.json.return_value = {
            "result": base64.b64encode(f"eval-v{version}".encode()).decode()
        }
        return resp

    req = BlindRequest(
        encryptedPersonalId=blinded_input(),
        recipientOrganization=RecipientOrganizationOin(TEST_OIN_WITH_PREFIX),
        recipientScope="scope",
    )

    with patch("requests.Session.request", side_effect=fake_post):
        result = service.eval_blind(req, pub)

    assert result.key_versions == (1, 3, 5)

    token = jwelib.JWE()
    token.deserialize(result.jwe)
    token.decrypt(key)
    body = json.loads(token.payload.decode("utf-8"))

    # Only the versions active *now* are evaluated: v3 and v5. The expired (v1)
    # and not-yet-started (v8) versions are excluded by date. The latest active
    # version (v5) is the subject; older active versions are carried separately.
    assert (
        body["subject"]
        == "pseudonym:eval:" + base64.urlsafe_b64encode(b"eval-v5").decode()
    )
    assert body["extraVersions"] == {
        "1": base64.urlsafe_b64encode(b"eval-v1").decode(),
        "3": base64.urlsafe_b64encode(b"eval-v3").decode(),
    }


def test_eval_via_hsm_without_service_raises() -> None:
    org_service = MagicMock()
    org_service.get_by_oin.return_value = SimpleNamespace(id=SimpleNamespace())
    evaluator = HsmOprfEvaluator(
        client=hsm_client(),
        hsm_key_version_service=None,  # type: ignore[arg-type]
    )

    with pytest.raises(
        AttributeError,
        match="has no attribute 'get_active_version_numbers_by_organization_oin'",
    ):
        evaluator.evaluate(TEST_OIN, b"blinded")


def test_eval_generate_key_without_result_raises_value_error() -> None:
    evaluator = HsmOprfEvaluator(
        client=hsm_client(),
        hsm_key_version_service=MagicMock(),
    )

    with (
        patch.object(evaluator._client, "post", return_value={}) as hsm_post,
        pytest.raises(ValueError, match="could not generate key"),
    ):
        evaluator._client.generate_oprf_key(
            str(OprfHsmKeyLabel(RecipientOrganizationOin(TEST_OIN_WITH_PREFIX), 1))
        )

    assert hsm_post.call_count == 1


def test_local_mode_without_server_key_raises() -> None:
    with pytest.raises(ValueError):
        service = OprfService(LocalOprfEvaluator(b""))
        service.eval_blind(
            BlindRequest(
                encryptedPersonalId=blinded_input(),
                recipientOrganization=RecipientOrganizationOin(TEST_OIN_WITH_PREFIX),
                recipientScope="scope",
            ),
            pub_key=jwk.JWK.generate(kty="RSA", size=2048),
        )
