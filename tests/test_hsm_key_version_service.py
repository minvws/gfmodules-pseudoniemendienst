import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.config import ConfigOprf
from app.db.db import Database
from app.db.entities.hsm_key_versions import HsmKeyVersion
from app.db.entities.organization import Organization
from app.models.oin import Oin, RecipientOrganizationOin
from app.models.requests import BlindRequest
from app.rid import RidUsage
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.oprf.oprf_service import OprfService
from app.services.org_service import OrgService

TEST_OIN = Oin("00000099000000001000")
TEST_OIN_WITH_PREFIX = f"oin:{TEST_OIN}"
TEST_OIN_111 = Oin("00000099000000011000")
TEST_OIN_222 = Oin("00000099000000022000")
TEST_OIN_333 = Oin("00000099000000033000")
TEST_OIN_444 = Oin("00000099000000044000")
TEST_OIN_555 = Oin("00000099000000055000")
TEST_OIN_78000 = Oin("00000000012345678000")
TEST_OIN_79000 = Oin("00000000012345679000")


def add_hsm_key_version(
    db: Database, oin: Oin, **kwargs: object
) -> tuple[HsmKeyVersion, Organization]:
    with db.get_db_session() as session:
        org = session.query(Organization).filter(Organization.oin == oin.value).first()
        if org is None:
            org = Organization(
                oin=oin,
                name=f"org-{oin.value}",
                max_rid_usage=RidUsage.IrreversiblePseudonym.value,
            )
            session.add(org)
            session.flush()
        version = HsmKeyVersion(organization_id=org.id, **kwargs)
        session.add(version)
        session.commit()
    return version, org


def test_get_active_versions_filters_by_date_and_removed(database: Database) -> None:
    now = datetime.now(timezone.utc)
    # active: started, no end date
    add_hsm_key_version(
        database,
        oin=TEST_OIN_111,
        version=1,
        from_dt=now - timedelta(days=1),
        until_dt=None,
    )
    # active: within window
    add_hsm_key_version(
        database,
        oin=TEST_OIN_222,
        version=2,
        from_dt=now - timedelta(days=1),
        until_dt=now + timedelta(days=1),
    )
    # inactive: not started yet
    add_hsm_key_version(
        database,
        oin=TEST_OIN_333,
        version=3,
        from_dt=now + timedelta(days=1),
        until_dt=None,
    )
    # inactive: already ended
    add_hsm_key_version(
        database,
        oin=TEST_OIN_444,
        version=4,
        from_dt=now - timedelta(days=2),
        until_dt=now - timedelta(days=1),
    )
    # inactive: removed
    add_hsm_key_version(
        database,
        oin=TEST_OIN_555,
        version=5,
        from_dt=now - timedelta(days=1),
        until_dt=None,
        removed=True,
    )

    service = HsmKeyVersionService(database)
    test_oins = [TEST_OIN_111, TEST_OIN_222, TEST_OIN_333, TEST_OIN_444, TEST_OIN_555]

    with database.get_db_session() as session:
        org_ids = [
            org.id
            for org in session.query(Organization)
            .filter(Organization.oin.in_([oin.value for oin in test_oins]))
            .all()
        ]

    active_versions = {
        v.version
        for org_id in org_ids
        for v in service.get_active_versions_by_organization_id(org_id)
    }

    assert active_versions == {1, 2}


def test_get_active_versions_excludes_version_ending_now(database: Database) -> None:
    now = datetime.now(timezone.utc)
    _, org = add_hsm_key_version(
        database,
        oin=TEST_OIN_111,
        version=1,
        from_dt=now - timedelta(hours=1),
        until_dt=now,
    )

    service = HsmKeyVersionService(database)
    active = {
        v.version
        for v in service.get_active_versions_by_organization_id(org.id, at=now)
    }

    assert active == set()

    # The same row is considered expired at this exact boundary.
    expired = {v.version for v in service.get_expired_versions(at=now)}
    assert expired == {1}


def test_get_active_or_create_version_numbers_returns_existing_active(
    database: Database,
) -> None:
    now = datetime.now(timezone.utc)
    _, org = add_hsm_key_version(
        database,
        oin=TEST_OIN_111,
        version=1,
        from_dt=now - timedelta(days=1),
        until_dt=None,
    )
    org_id = org.id
    add_hsm_key_version(
        database,
        oin=TEST_OIN_111,
        version=2,
        from_dt=now - timedelta(hours=1),
        until_dt=None,
    )

    service = HsmKeyVersionService(database)
    versions = service.get_active_or_create_version_numbers_by_organization_id(org_id)

    assert versions == [1, 2]


def test_get_active_or_create_version_numbers_creates_when_none_active(
    database: Database,
) -> None:
    now = datetime.now(timezone.utc)
    _, org = add_hsm_key_version(
        database,
        oin=TEST_OIN_111,
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )
    org_id = org.id

    service = HsmKeyVersionService(database)
    versions = service.get_active_or_create_version_numbers_by_organization_id(org_id)

    assert versions == [2]

    all_versions = service.get_versions_by_organization_id(org_id)
    assert [v.version for v in all_versions] == [1, 2]

    created_version = next(v for v in all_versions if v.version == 2)
    assert created_version.from_dt >= now


def test_eval_via_hsm_returns_entry_per_active_version(
    database: Database,
    org_service: OrgService,
) -> None:
    now = datetime.now(timezone.utc)
    add_hsm_key_version(
        database,
        oin=TEST_OIN_78000,
        version=2,
        from_dt=now - timedelta(days=2),
    )
    add_hsm_key_version(
        database,
        oin=TEST_OIN_78000,
        version=7,
        from_dt=now - timedelta(days=1),
    )
    # a removed version must be ignored
    add_hsm_key_version(
        database,
        oin=TEST_OIN_78000,
        version=9,
        from_dt=now - timedelta(days=1),
        removed=True,
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=org_service,
    )

    with (
        patch.object(service, "_label_exists", return_value=True) as label_exists,
        patch.object(
            service, "_evaluate_label", return_value=b"evaluated"
        ) as evaluate_label,
    ):
        result = service._eval_via_hsm(TEST_OIN_78000, b"blinded")

    assert result == {2: b"evaluated", 7: b"evaluated"}

    assert [str(c.args[0]) for c in label_exists.call_args_list] == [
        "oin-00000000012345678000-v2",
        "oin-00000000012345678000-v7",
    ]

    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        ("oin-00000000012345678000-v2", b"blinded"),
        ("oin-00000000012345678000-v7", b"blinded"),
    ]

    assert label_exists.call_count == 2
    assert evaluate_label.call_count == 2


def test_eval_generates_keys_if_needed(
    database: Database, org_service: OrgService
) -> None:
    now = datetime.now(timezone.utc)
    add_hsm_key_version(
        database,
        oin=TEST_OIN_79000,
        version=1,
        from_dt=now - timedelta(days=2),
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=org_service,
    )

    with (
        patch.object(service, "_label_exists", return_value=False) as label_exists,
        patch.object(service, "_generate_key") as generate_key,
        patch.object(
            service, "_evaluate_label", return_value=b"evaluated"
        ) as evaluate_label,
    ):
        result = service._eval_via_hsm(TEST_OIN_79000, b"blinded")

    assert result == {1: b"evaluated"}

    assert [str(c.args[0]) for c in label_exists.call_args_list] == [
        "oin-00000000012345679000-v1",
    ]

    assert [str(c.args[0]) for c in generate_key.call_args_list] == [
        "oin-00000000012345679000-v1",
    ]

    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        ("oin-00000000012345679000-v1", b"blinded"),
    ]

    assert label_exists.call_count == 1
    assert evaluate_label.call_count == 1
    assert generate_key.call_count == 1


def test_eval_blind_subject_is_latest_with_extra_versions(
    database: Database,
    org_service: OrgService,
) -> None:
    from jwcrypto import jwe as jwelib
    from jwcrypto import jwk

    from app.models.requests import BlindRequest

    now = datetime.now(timezone.utc)
    add_hsm_key_version(
        database,
        oin=TEST_OIN_78000,
        version=2,
        from_dt=now - timedelta(days=2),
    )
    add_hsm_key_version(
        database,
        oin=TEST_OIN_78000,
        version=7,
        from_dt=now - timedelta(days=1),
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=org_service,
    )

    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    def fake_post(url: str, json: dict, **kwargs: object) -> MagicMock:  # type: ignore[type-arg]
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
        encryptedPersonalId=base64.urlsafe_b64encode(b"blinded").decode(),
        recipientOrganization=RecipientOrganizationOin("oin:00000000012345678000"),
        recipientScope="scope",
    )

    with patch("app.services.oprf.oprf_service.requests.post", side_effect=fake_post):
        result = service.eval_blind(req, pub, None)

    assert result.key_versions == (2, 7)

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
    assert body["extra_versions"] == {
        "2": base64.urlsafe_b64encode(b"eval-v2").decode()
    }


def test_eval_blind_jwe_contains_only_versions_active_at_date(
    database: Database,
    org_service: OrgService,
) -> None:
    from jwcrypto import jwe as jwelib
    from jwcrypto import jwk

    from app.models.requests import BlindRequest

    now = datetime.now(timezone.utc)
    # expired: ended yesterday -> excluded
    add_hsm_key_version(
        database,
        oin=TEST_OIN,
        version=1,
        from_dt=now - timedelta(days=10),
        until_dt=now - timedelta(days=1),
    )
    # active: started, no end date
    add_hsm_key_version(
        database,
        oin=TEST_OIN,
        version=3,
        from_dt=now - timedelta(days=5),
        until_dt=None,
    )
    # active: within window
    add_hsm_key_version(
        database,
        oin=TEST_OIN,
        version=5,
        from_dt=now - timedelta(days=2),
        until_dt=now + timedelta(days=2),
    )
    # future: not started yet -> excluded
    add_hsm_key_version(
        database,
        oin=TEST_OIN,
        version=8,
        from_dt=now + timedelta(days=1),
        until_dt=None,
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=org_service,
    )

    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())

    def fake_post(url: str, json: dict, **kwargs: object) -> MagicMock:  # type: ignore[type-arg]
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
        encryptedPersonalId=base64.urlsafe_b64encode(b"blinded").decode(),
        recipientOrganization=RecipientOrganizationOin(TEST_OIN_WITH_PREFIX),
        recipientScope="scope",
    )

    with patch("app.services.oprf.oprf_service.requests.post", side_effect=fake_post):
        result = service.eval_blind(req, pub, None)

    assert result.key_versions == (3, 5)

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
    assert body["extra_versions"] == {
        "3": base64.urlsafe_b64encode(b"eval-v3").decode()
    }


def test_eval_via_hsm_without_active_version_creates_one(
    database: Database,
    org_service: OrgService,
) -> None:
    org_service.create(
        oin=TEST_OIN,
        name=f"Integration OPRF Service Org {TEST_OIN}",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=org_service,
    )

    with (
        patch.object(service, "_label_exists", return_value=False) as label_exists,
        patch.object(service, "_generate_key") as generate_key,
        patch.object(
            service, "_evaluate_label", return_value=b"evaluated"
        ) as evaluate_label,
    ):
        result = service._eval_via_hsm(TEST_OIN, b"blinded")

    assert result == {1: b"evaluated"}

    assert [str(c.args[0]) for c in label_exists.call_args_list] == [
        "oin-00000099000000001000-v1",
    ]

    assert [str(c.args[0]) for c in generate_key.call_args_list] == [
        "oin-00000099000000001000-v1",
    ]

    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        ("oin-00000099000000001000-v1", b"blinded"),
    ]

    assert label_exists.call_count == 1
    assert evaluate_label.call_count == 1
    assert generate_key.call_count == 1


def test_eval_blind_without_active_versions_creates_active_version(
    database: Database,
    org_service: OrgService,
) -> None:
    org = org_service.create(
        oin=TEST_OIN,
        name="Evaluation OPRF Service Org",
        max_key_usage=RidUsage.ReversiblePseudonym,
    )

    service = OprfService(
        server_key=None,
        hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
        hsm_key_version_service=HsmKeyVersionService(database),
        org_service=org_service,
    )

    from jwcrypto import jwk

    key = jwk.JWK.generate(kty="RSA", size=2048)
    pub = jwk.JWK.from_json(key.export_public())
    req = BlindRequest(
        encryptedPersonalId=base64.urlsafe_b64encode(b"blinded").decode(),
        recipientOrganization=RecipientOrganizationOin(TEST_OIN_WITH_PREFIX),
        recipientScope="scope",
    )

    with (
        patch.object(service, "_label_exists", return_value=False) as label_exists,
        patch.object(service, "_generate_key") as generate_key,
        patch.object(
            service, "_evaluate_label", return_value=b"evaluated"
        ) as evaluate_label,
    ):
        result = service.eval_blind(req, pub, None)

    assert result.key_versions == (1,)

    assert [str(c.args[0]) for c in label_exists.call_args_list] == [
        f"oin-{RecipientOrganizationOin(TEST_OIN_WITH_PREFIX)}-v1",
    ]
    assert [str(c.args[0]) for c in generate_key.call_args_list] == [
        f"oin-{RecipientOrganizationOin(TEST_OIN_WITH_PREFIX)}-v1",
    ]
    assert [(str(c.args[0]), c.args[1]) for c in evaluate_label.call_args_list] == [
        (f"oin-{RecipientOrganizationOin(TEST_OIN_WITH_PREFIX)}-v1", b"blinded"),
    ]

    version_service = HsmKeyVersionService(database)
    versions = version_service.get_versions_by_organization_id(org.id)
    assert [v.version for v in versions] == [1]


def test_eval_via_hsm_without_service_raises() -> None:
    org_service = MagicMock()
    org_service.get_by_oin.return_value = SimpleNamespace(id=SimpleNamespace())
    with pytest.raises(ValueError, match="HSM key version service not configured"):
        OprfService(
            server_key=None,
            hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
            org_service=org_service,
        )


def test_eval_via_hsm_without_org_service_raises() -> None:
    with pytest.raises(ValueError, match="org service not configured"):
        OprfService(
            server_key=None,
            hsm_config=ConfigOprf(hsm_url="https://hsm.local"),
            hsm_key_version_service=MagicMock(),
        )


def test_local_mode_without_server_key_raises() -> None:
    with pytest.raises(ValueError, match="server key not configured"):
        OprfService(server_key=None)
