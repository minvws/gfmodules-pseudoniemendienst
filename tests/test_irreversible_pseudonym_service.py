import base64
import hashlib
import hmac
import os
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from test_reversible_pseudonym_service import FakeHsm, _with_fake_hsm

from app.config import ConfigOprf
from app.models.oin import Oin, RecipientOrganizationOin
from app.personal_id import PersonalId
from app.services.hsm.client import HsmClient
from app.services.irreversible.keys import (
    HsmIrreversibleKeyOperations,
    IrreversibleKeyLabel,
    LocalIrreversibleKeyOperations,
)
from app.services.irreversible.service import (
    IrreversiblePseudonymError,
    IrreversiblePseudonymService,
)
from app.services.reversible.keys import LocalReversibleKeyOperations

OIN = Oin("00000099000000001000")
OTHER_OIN = Oin("00000099000000002000")
PID = PersonalId.from_str("NL:bsn:950000012")
OTHER_PID = PersonalId.from_str("NL:bsn:950000024")
SCOPE = "nvi"


def _key_versions(active: dict[Oin, list[int]]) -> MagicMock:
    service = MagicMock()
    service.get_active_version_numbers_by_organization_oin.side_effect = lambda oin: (
        active[oin]
    )
    return service


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def service(master_key: bytes) -> IrreversiblePseudonymService:
    return IrreversiblePseudonymService(
        LocalIrreversibleKeyOperations(master_key),
        _key_versions({OIN: [1], OTHER_OIN: [1]}),
    )


def test_pseudonym_is_a_base64url_sha256_digest_and_deterministic(
    service: IrreversiblePseudonymService,
) -> None:
    first = service.generate(PID, OIN, SCOPE)
    second = service.generate(PID, OIN, SCOPE)

    assert first == second
    assert first.version == 1
    assert first.older == {}
    assert len(base64.urlsafe_b64decode(first.value)) == hashlib.sha256().digest_size


def test_pseudonym_matches_reference_computation(master_key: bytes) -> None:
    keys = LocalIrreversibleKeyOperations(master_key)
    service = IrreversiblePseudonymService(keys, _key_versions({OIN: [1]}))

    subject = f"NL:bsn:950000012|oin:{OIN}|{SCOPE}".encode()
    expected = base64.urlsafe_b64encode(keys.hmac(OIN, 1, subject)).decode("ascii")

    assert service.generate(PID, OIN, SCOPE).value == expected


@pytest.mark.parametrize(
    "pid,recipient,scope",
    [
        (OTHER_PID, OIN, SCOPE),
        (PID, OTHER_OIN, SCOPE),
        (PID, OIN, "other"),
    ],
)
def test_pseudonym_changes_with_personal_id_recipient_and_scope(
    service: IrreversiblePseudonymService, pid: PersonalId, recipient: Oin, scope: str
) -> None:
    assert service.generate(pid, recipient, scope) != service.generate(PID, OIN, SCOPE)


def test_recipient_oin_with_prefix_gives_the_same_pseudonym(
    service: IrreversiblePseudonymService,
) -> None:
    plain = service.generate(PID, OIN, SCOPE)
    prefixed = service.generate(PID, RecipientOrganizationOin(f"oin:{OIN}"), SCOPE)

    assert plain == prefixed


def test_key_version_changes_the_pseudonym(master_key: bytes) -> None:
    keys = LocalIrreversibleKeyOperations(master_key)
    v1 = IrreversiblePseudonymService(keys, _key_versions({OIN: [1]}))
    v2 = IrreversiblePseudonymService(keys, _key_versions({OIN: [2]}))

    assert v1.generate(PID, OIN, SCOPE).value != v2.generate(PID, OIN, SCOPE).value


def test_dual_version_during_grace_carries_the_older_pseudonym(
    master_key: bytes,
) -> None:
    keys = LocalIrreversibleKeyOperations(master_key)
    before = IrreversiblePseudonymService(keys, _key_versions({OIN: [1]}))
    during = IrreversiblePseudonymService(keys, _key_versions({OIN: [1, 2]}))
    after = IrreversiblePseudonymService(keys, _key_versions({OIN: [2]}))

    old = before.generate(PID, OIN, SCOPE)
    dual = during.generate(PID, OIN, SCOPE)
    new = after.generate(PID, OIN, SCOPE)

    assert dual.version == 2
    assert dual.value == new.value
    assert dual.older == {1: old.value}
    assert new.older == {}


def test_irreversible_keys_are_separate_from_reversible_keys(
    master_key: bytes,
) -> None:
    data = b"same input"

    irreversible = LocalIrreversibleKeyOperations(master_key).hmac(OIN, 1, data)
    reversible = LocalReversibleKeyOperations(master_key).hmac(OIN, 1, data)

    assert irreversible != reversible


def test_no_active_key_version_is_reported(master_key: bytes) -> None:
    service = IrreversiblePseudonymService(
        LocalIrreversibleKeyOperations(master_key), _key_versions({OIN: []})
    )

    with pytest.raises(IrreversiblePseudonymError) as e:
        service.generate(PID, OIN, SCOPE)

    assert e.value.error_type == "no_active_key_version"


def test_scope_with_delimiter_is_refused(service: IrreversiblePseudonymService) -> None:
    with pytest.raises(IrreversiblePseudonymError) as e:
        service.generate(PID, OIN, "a|b")

    assert e.value.error_type == "crypto_failure"


@pytest.fixture
def hsm_service() -> IrreversiblePseudonymService:
    return IrreversiblePseudonymService(
        HsmIrreversibleKeyOperations(
            HsmClient(ConfigOprf(hsm_url="https://hsm.local"))
        ),
        _key_versions({OIN: [1]}),
    )


def test_hsm_secret_is_created_once_under_its_own_label(
    hsm_service: IrreversiblePseudonymService,
) -> None:
    fake = FakeHsm()
    label = str(IrreversibleKeyLabel(OIN, 1))

    with _with_fake_hsm(fake):
        first = hsm_service.generate(PID, OIN, SCOPE)
        second = hsm_service.generate(PID, OIN, SCOPE)

    assert label == f"oin-{OIN}-irp-v1-hmac"
    assert set(fake.keys) == {label}
    assert first == second
    generate_calls = [c for c in fake.calls if c[0] == "/generate/secret"]
    assert len(generate_calls) == 1

    subject = f"NL:bsn:950000012|oin:{OIN}|{SCOPE}".encode()
    expected = hmac.new(fake.keys[label], subject, hashlib.sha256).digest()
    assert base64.urlsafe_b64decode(first.value) == expected


def test_hsm_unreachable_is_reported(
    hsm_service: IrreversiblePseudonymService,
) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise requests.exceptions.ConnectionError("refused")

    with _with_fake_hsm(FakeHsm()) as post:
        post.side_effect = refuse
        with pytest.raises(IrreversiblePseudonymError) as e:
            hsm_service.generate(PID, OIN, SCOPE)

    assert e.value.error_type == "hsm_unreachable"
