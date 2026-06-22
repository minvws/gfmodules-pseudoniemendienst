import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.config import ConfigOprf
from app.db.db import Database
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.entities.organization import Organization
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.oprf.oprf_service import OprfService


def _add(db: Database, oin: str, **kwargs: object) -> None:
    with db.get_db_session() as session:
        org = session.query(Organization).filter(Organization.oin == oin).first()
        if org is None:
            org = Organization(oin=oin, name=f"org-{oin}", max_rid_usage="irp")
            session.add(org)
            session.flush()
        session.add(HsmKeyVersion(organization_id=org.id, **kwargs))
        session.commit()


def test_get_active_versions_filters_by_date_and_removed(database: Database) -> None:
    now = datetime.now(timezone.utc)
    # active: started, no end date
    _add(database, oin="111", version=1, from_dt=now - timedelta(days=1), until_dt=None)
    # active: within window
    _add(
        database,
        oin="222",
        version=2,
        from_dt=now - timedelta(days=1),
        until_dt=now + timedelta(days=1),
    )
    # inactive: not started yet
    _add(database, oin="333", version=3, from_dt=now + timedelta(days=1), until_dt=None)
    # inactive: already ended
    _add(
        database,
        oin="444",
        version=4,
        from_dt=now - timedelta(days=2),
        until_dt=now - timedelta(days=1),
    )
    # inactive: removed
    _add(
        database,
        oin="555",
        version=5,
        from_dt=now - timedelta(days=1),
        until_dt=None,
        removed=True,
    )

    service = HsmKeyVersionService(database)
    active = {v.oin for v in service.get_active_versions()}

    assert active == {"111", "222"}


def test_eval_via_hsm_returns_entry_per_active_version(database: Database) -> None:
    now = datetime.now(timezone.utc)
    _add(database, oin="12345678", version=2, from_dt=now - timedelta(days=2))
    _add(database, oin="12345678", version=7, from_dt=now - timedelta(days=1))
    # a removed version must be ignored
    _add(
        database,
        oin="12345678",
        version=9,
        from_dt=now - timedelta(days=1),
        removed=True,
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
    )

    response = MagicMock()
    response.json.return_value = {"result": base64.b64encode(b"evaluated").decode()}
    with patch(
        "app.services.oprf.oprf_service.requests.post", return_value=response
    ) as post:
        result = service._eval_via_hsm("oin:12345678", b"blinded")

    assert result == {2: b"evaluated", 7: b"evaluated"}
    labels = {call.kwargs["json"]["label"] for call in post.call_args_list}
    assert labels == {"oin-oin:12345678-v2", "oin-oin:12345678-v7"}


def test_eval_blind_subject_is_latest_with_extra_versions(database: Database) -> None:
    from jwcrypto import jwe as jwelib
    from jwcrypto import jwk

    from app.models.requests import BlindRequest

    now = datetime.now(timezone.utc)
    _add(database, oin="12345678", version=2, from_dt=now - timedelta(days=2))
    _add(database, oin="12345678", version=7, from_dt=now - timedelta(days=1))

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
    )

    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    def fake_post(url: str, json: dict, **kwargs: object) -> MagicMock:  # type: ignore[type-arg]
        version = json["label"].rsplit("v", 1)[-1]
        resp = MagicMock()
        resp.json.return_value = {
            "result": base64.b64encode(f"eval-v{version}".encode()).decode()
        }
        return resp

    req = BlindRequest(
        encryptedPersonalId=base64.urlsafe_b64encode(b"blinded").decode(),
        recipientOrganization="oin:12345678",
        recipientScope="scope",
    )

    with patch("app.services.oprf.oprf_service.requests.post", side_effect=fake_post):
        token_str = service.eval_blind(req, pub)

    token = jwelib.JWE()
    token.deserialize(token_str)
    token.decrypt(key)
    body = json.loads(token.payload.decode("utf-8"))

    # The subject holds the latest version (v7) in the original format.
    assert (
        body["subject"]
        == "pseudonym:eval:" + base64.urlsafe_b64encode(b"eval-v7").decode()
    )
    # Older versions are carried separately so newer clients can detect them.
    assert body["extra_versions"] == {
        "2": base64.urlsafe_b64encode(b"eval-v2").decode()
    }


def test_eval_blind_jwe_contains_only_versions_active_at_date(
    database: Database,
) -> None:
    from jwcrypto import jwe as jwelib
    from jwcrypto import jwk

    from app.models.requests import BlindRequest

    now = datetime.now(timezone.utc)
    # expired: ended yesterday -> excluded
    _add(
        database,
        oin="00000099000000001000",
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )
    # active: started, no end date
    _add(
        database,
        oin="00000099000000001000",
        version=3,
        from_dt=now - timedelta(days=5),
        until_dt=None,
    )
    # active: within window
    _add(
        database,
        oin="00000099000000001000",
        version=5,
        from_dt=now - timedelta(days=2),
        until_dt=now + timedelta(days=2),
    )
    # future: not started yet -> excluded
    _add(
        database,
        oin="00000099000000001000",
        version=8,
        from_dt=now + timedelta(days=1),
        until_dt=None,
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
    )

    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    def fake_post(url: str, json: dict, **kwargs: object) -> MagicMock:  # type: ignore[type-arg]
        version = json["label"].rsplit("v", 1)[-1]
        resp = MagicMock()
        resp.json.return_value = {
            "result": base64.b64encode(f"eval-v{version}".encode()).decode()
        }
        return resp

    req = BlindRequest(
        encryptedPersonalId=base64.urlsafe_b64encode(b"blinded").decode(),
        recipientOrganization="oin:00000099000000001000",
        recipientScope="scope",
    )

    with patch("app.services.oprf.oprf_service.requests.post", side_effect=fake_post):
        token_str = service.eval_blind(req, pub)

    token = jwelib.JWE()
    token.deserialize(token_str)
    token.decrypt(key)
    body = json.loads(token.payload.decode("utf-8"))

    # Only the versions active *now* are evaluated: v3 and v5. The expired (v1)
    # and not-yet-started (v8) versions are excluded by date. The latest active
    # version (v5) is the subject; older active versions are carried separately.
    assert (
        body["subject"]
        == "pseudonym:eval:" + base64.urlsafe_b64encode(b"eval-v5").decode()
    )
    assert body["extra_versions"] == {
        "3": base64.urlsafe_b64encode(b"eval-v3").decode()
    }


def test_eval_via_hsm_without_active_version_raises(database: Database) -> None:
    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
    )
    target = "00000099000000001000"
    with pytest.raises(ValueError, match=f"no active key version for oin {target}"):
        service._eval_via_hsm(f"oin:{target}", b"blinded")


def test_eval_via_hsm_without_service_raises() -> None:
    service = OprfService(
        server_key=None, hsm_config=ConfigOprf(hsm_url="https://hsm.local")
    )

    with pytest.raises(ValueError, match="HSM key version service not configured"):
        service._eval_via_hsm("oin:12345678", b"blinded")
