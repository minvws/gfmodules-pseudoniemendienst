import base64
import hashlib
import hmac
import os
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.config import ConfigOprf
from app.models.oin import Oin, RecipientOrganizationOin
from app.personal_id import PersonalId
from app.services.hsm.client import HsmClient
from app.services.reversible.keys import (
    HsmReversibleKeyOperations,
    LocalReversibleKeyOperations,
    ReversibleKeyLabel,
    ReversibleKeyOperations,
)
from app.services.reversible.service import (
    FORMAT_VERSION,
    IV_LENGTH,
    ReversiblePseudonymError,
    ReversiblePseudonymService,
)

OIN = Oin("00000099000000001000")
OTHER_OIN = Oin("00000099000000002000")
PID = PersonalId.from_str("NL:bsn:950000012")
SCOPE = "nvi"


def _key_versions(
    active: dict[Oin, list[int]], known: dict[Oin, list[tuple[int, bool]]] | None = None
) -> MagicMock:
    """Stub of HsmKeyVersionService keyed by organization OIN: ``active`` gives
    the active version numbers, ``known`` all (version, removed) rows (defaults
    to the active ones, not removed)."""
    service = MagicMock()
    service.get_active_version_numbers_by_organization_oin.side_effect = lambda oin: (
        active[oin]
    )

    def _versions(oin: Oin) -> list[Any]:
        rows = (known or {}).get(oin) or [(v, False) for v in active[oin]]
        return [
            MagicMock(
                version=v, removed_at=datetime.now(timezone.utc) if removed else None
            )
            for v, removed in rows
        ]

    service.get_versions_by_organization_id.side_effect = _versions
    return service


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def local_keys(master_key: bytes) -> LocalReversibleKeyOperations:
    return LocalReversibleKeyOperations(master_key)


@pytest.fixture
def recipient() -> Oin:
    return OIN


@pytest.fixture
def service(
    local_keys: LocalReversibleKeyOperations, recipient: Oin
) -> ReversiblePseudonymService:
    return ReversiblePseudonymService(local_keys, _key_versions({recipient: [1]}))


# --- reference implementation of PRS-AK-F0XF, independent of the code under test


def _reference(k_hmac: bytes, k_aes: bytes, subject: bytes, version: int) -> str:
    inner = hmac.new(k_hmac, subject, hashlib.sha256).digest()
    iv = hmac.new(k_hmac, inner, hashlib.sha256).digest()[:16]
    padder = padding.PKCS7(128).padder()
    padded = padder.update(subject) + padder.finalize()
    enc = Cipher(algorithms.AES(k_aes), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    blob = bytes([FORMAT_VERSION]) + version.to_bytes(2, "big") + ct + iv
    return base64.urlsafe_b64encode(blob).decode()


def test_matches_reference_construction(
    master_key: bytes, local_keys: LocalReversibleKeyOperations, recipient: Oin
) -> None:
    service = ReversiblePseudonymService(local_keys, _key_versions({recipient: [3]}))

    result = service.generate(PID, recipient, SCOPE)

    subject = f"{PID.as_str()}|oin:{OIN.value}|{SCOPE}".encode()
    expected = _reference(
        local_keys._key(OIN, 3, "hmac"), local_keys._key(OIN, 3, "aes"), subject, 3
    )
    assert result.value == expected
    assert result.version == 3


def test_pseudonym_is_deterministic(
    service: ReversiblePseudonymService, recipient: Oin
) -> None:
    assert service.generate(PID, recipient, SCOPE) == service.generate(
        PID, recipient, SCOPE
    )


def test_pseudonym_changes_with_input_scope_organization_and_version(
    local_keys: LocalReversibleKeyOperations,
) -> None:
    service = ReversiblePseudonymService(
        local_keys, _key_versions({OIN: [1], OTHER_OIN: [1]})
    )
    base = service.generate(PID, OIN, SCOPE).value

    assert (
        service.generate(PersonalId.from_str("NL:bsn:950000024"), OIN, SCOPE).value
        != base
    )
    assert service.generate(PID, OIN, "other").value != base
    assert service.generate(PID, OTHER_OIN, SCOPE).value != base

    rotated = ReversiblePseudonymService(local_keys, _key_versions({OIN: [1, 2]}))
    assert rotated.generate(PID, OIN, SCOPE).value != base


def test_recipient_with_prefix_gives_the_same_pseudonym(
    service: ReversiblePseudonymService, recipient: Oin
) -> None:
    """The router hands over the request's RecipientOrganizationOin; its "oin:"
    prefix must not leak into the subject or the key labels."""
    prefixed = RecipientOrganizationOin(f"oin:{recipient.value}")

    assert service.generate(PID, prefixed, SCOPE) == service.generate(
        PID, recipient, SCOPE
    )
    assert str(ReversibleKeyLabel(prefixed, 1, "aes")) == str(
        ReversibleKeyLabel(recipient, 1, "aes")
    )


def test_roundtrip(service: ReversiblePseudonymService, recipient: Oin) -> None:
    pseudonym = service.generate(PID, recipient, SCOPE)

    reversed_ = service.reverse(pseudonym.value, recipient)

    assert reversed_.personal_id == PID
    assert reversed_.recipient_organization == f"oin:{OIN.value}"
    assert reversed_.recipient_scope == SCOPE
    assert reversed_.version == 1


def test_latest_active_version_is_used_and_older_ones_still_reverse(
    local_keys: LocalReversibleKeyOperations, recipient: Oin
) -> None:
    v1 = ReversiblePseudonymService(local_keys, _key_versions({recipient: [1]}))
    old = v1.generate(PID, recipient, SCOPE)

    rotated = ReversiblePseudonymService(local_keys, _key_versions({recipient: [1, 2]}))
    new = rotated.generate(PID, recipient, SCOPE)

    assert new.version == 2
    assert rotated.reverse(old.value, recipient).version == 1
    assert rotated.reverse(new.value, recipient).personal_id == PID


def test_without_active_version_generation_fails(
    local_keys: LocalReversibleKeyOperations, recipient: Oin
) -> None:
    service = ReversiblePseudonymService(local_keys, _key_versions({recipient: []}))

    with pytest.raises(ReversiblePseudonymError) as e:
        service.generate(PID, recipient, SCOPE)
    assert e.value.error_type == "no_active_key_version"


def test_reverse_for_another_organization_fails(
    local_keys: LocalReversibleKeyOperations,
) -> None:
    service = ReversiblePseudonymService(
        local_keys, _key_versions({OIN: [1], OTHER_OIN: [1]})
    )
    pseudonym = service.generate(PID, OIN, SCOPE)

    with pytest.raises(ReversiblePseudonymError) as e:
        service.reverse(pseudonym.value, OTHER_OIN)
    assert e.value.error_type == "invalid_pseudonym"


def test_reverse_with_destroyed_version_fails(
    local_keys: LocalReversibleKeyOperations, recipient: Oin
) -> None:
    pseudonym = ReversiblePseudonymService(
        local_keys, _key_versions({recipient: [1]})
    ).generate(PID, recipient, SCOPE)

    later = ReversiblePseudonymService(
        local_keys,
        _key_versions({recipient: [2]}, {recipient: [(1, True), (2, False)]}),
    )
    with pytest.raises(ReversiblePseudonymError) as e:
        later.reverse(pseudonym.value, recipient)
    assert e.value.error_type == "version_destroyed"


def _flip(value: str, index: int) -> str:
    blob = bytearray(base64.urlsafe_b64decode(value))
    blob[index] ^= 0x01
    return base64.urlsafe_b64encode(bytes(blob)).decode()


def test_tampered_pseudonym_is_rejected(
    service: ReversiblePseudonymService, recipient: Oin
) -> None:
    value = service.generate(PID, recipient, SCOPE).value
    length = len(base64.urlsafe_b64decode(value))

    for index in (3, length - IV_LENGTH - 1, length - 1):
        with pytest.raises(ReversiblePseudonymError) as e:
            service.reverse(_flip(value, index), recipient)
        assert e.value.error_type == "invalid_pseudonym"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not base64!",
        base64.urlsafe_b64encode(b"\x02" + b"x" * 40).decode(),
        base64.urlsafe_b64encode(b"\x01\x00\x01" + b"x" * 33).decode(),
    ],
)
def test_malformed_pseudonym_is_rejected(
    service: ReversiblePseudonymService, recipient: Oin, value: str
) -> None:
    with pytest.raises(ReversiblePseudonymError) as e:
        service.reverse(value, recipient)
    assert e.value.error_type == "invalid_pseudonym"


def test_scope_with_separator_is_refused(
    service: ReversiblePseudonymService, recipient: Oin
) -> None:
    with pytest.raises(ReversiblePseudonymError):
        service.generate(PID, recipient, "a|b")


# --- HSM-backed key operations, against a fake HSM API


class FakeHsm:
    """Behaves like nl-rdo-hsm-api-service for the calls the PRS makes: keys are
    random bytes per label, sign is HMAC-SHA256, encrypt/decrypt is AES-CBC with
    PKCS#7 padding and the supplied IV."""

    def __init__(self) -> None:
        self.keys: dict[str, bytes] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def post(self, url: str, json: dict[str, Any], **kwargs: Any) -> MagicMock:
        path = url.split("/SoftHSMLabel", 1)[1]
        self.calls.append((path, json))
        resp = MagicMock()
        label = json["label"]
        if path == "":
            resp.json.return_value = {"objects": ["obj"] if label in self.keys else []}
        elif path in ("/generate/aes", "/generate/secret"):
            self.keys[label] = os.urandom(32)
            resp.json.return_value = {"result": "created"}
        elif path == "/sign":
            assert json["mechanism"] == "SHA256_HMAC"
            digest = hmac.new(
                self.keys[label], base64.b64decode(json["data"]), hashlib.sha256
            ).digest()
            resp.json.return_value = {
                "result": {"data": base64.b64encode(digest).decode()}
            }
        elif path in ("/encrypt", "/decrypt"):
            iv = base64.b64decode(json["iv"])
            data = base64.b64decode(json["data"])
            cipher = Cipher(algorithms.AES(self.keys[label]), modes.CBC(iv))
            if path == "/encrypt":
                padder = padding.PKCS7(128).padder()
                enc = cipher.encryptor()
                out = (
                    enc.update(padder.update(data) + padder.finalize()) + enc.finalize()
                )
            else:
                dec = cipher.decryptor()
                unpadder = padding.PKCS7(128).unpadder()
                out = (
                    unpadder.update(dec.update(data) + dec.finalize())
                    + unpadder.finalize()
                )
            resp.json.return_value = {
                "result": {"data": base64.b64encode(out).decode()}
            }
        else:
            raise AssertionError(f"unexpected HSM call {path}")
        return resp


@pytest.fixture
def fake_hsm() -> FakeHsm:
    return FakeHsm()


@pytest.fixture
def hsm_keys() -> ReversibleKeyOperations:
    return HsmReversibleKeyOperations(
        HsmClient(ConfigOprf(hsm_url="https://hsm.local"))
    )


def _with_fake_hsm(fake: FakeHsm) -> Any:
    return patch("app.services.hsm.client.requests.post", side_effect=fake.post)


def test_hsm_keys_are_created_once_and_pseudonym_matches_reference(
    hsm_keys: ReversibleKeyOperations, fake_hsm: FakeHsm, recipient: Oin
) -> None:
    service = ReversiblePseudonymService(hsm_keys, _key_versions({recipient: [1]}))

    with _with_fake_hsm(fake_hsm):
        first = service.generate(PID, recipient, SCOPE)
        second = service.generate(PID, recipient, SCOPE)

    assert first == second
    assert set(fake_hsm.keys) == {
        f"oin-{OIN}-rp-v1-aes",
        f"oin-{OIN}-rp-v1-hmac",
    }
    generated = [c for c in fake_hsm.calls if c[0].startswith("/generate/")]
    assert len(generated) == 2

    subject = f"{PID.as_str()}|oin:{OIN.value}|{SCOPE}".encode()
    assert first.value == _reference(
        fake_hsm.keys[f"oin-{OIN}-rp-v1-hmac"],
        fake_hsm.keys[f"oin-{OIN}-rp-v1-aes"],
        subject,
        1,
    )


def test_hsm_roundtrip(
    hsm_keys: ReversibleKeyOperations, fake_hsm: FakeHsm, recipient: Oin
) -> None:
    service = ReversiblePseudonymService(hsm_keys, _key_versions({recipient: [1]}))

    with _with_fake_hsm(fake_hsm):
        pseudonym = service.generate(PID, recipient, SCOPE)
        reversed_ = service.reverse(pseudonym.value, recipient)

    assert reversed_.personal_id == PID
    assert reversed_.recipient_scope == SCOPE


def test_hsm_unreachable_is_reported_as_such(
    hsm_keys: ReversibleKeyOperations, recipient: Oin
) -> None:
    service = ReversiblePseudonymService(hsm_keys, _key_versions({recipient: [1]}))

    with (
        patch(
            "app.services.hsm.client.requests.post",
            side_effect=requests.exceptions.ConnectionError("down"),
        ),
        pytest.raises(ReversiblePseudonymError) as e,
    ):
        service.generate(PID, recipient, SCOPE)
    assert e.value.error_type == "hsm_unreachable"


def test_hsm_error_is_reported_as_crypto_failure(
    hsm_keys: ReversibleKeyOperations, recipient: Oin
) -> None:
    service = ReversiblePseudonymService(hsm_keys, _key_versions({recipient: [1]}))
    failing = MagicMock()
    failing.raise_for_status.side_effect = requests.HTTPError("boom")

    with (
        patch("app.services.hsm.client.requests.post", return_value=failing),
        pytest.raises(ReversiblePseudonymError) as e,
    ):
        service.generate(PID, recipient, SCOPE)
    assert e.value.error_type == "crypto_failure"


def test_local_and_hsm_operations_are_interchangeable(
    fake_hsm: FakeHsm, recipient: Oin
) -> None:
    """A pseudonym made with keys in the HSM reverses with a local implementation
    holding the same key bytes, and vice versa: both do the same primitives."""

    class KnownKeys(LocalReversibleKeyOperations):
        def _key(self, oin: Oin, version: int, kind: str) -> bytes:
            return fake_hsm.keys[f"oin-{oin}-rp-v{version}-{kind}"]

    versions: Callable[[], MagicMock] = lambda: _key_versions({recipient: [1]})
    hsm_service = ReversiblePseudonymService(
        HsmReversibleKeyOperations(HsmClient(ConfigOprf(hsm_url="https://hsm.local"))),
        versions(),
    )
    with _with_fake_hsm(fake_hsm):
        from_hsm = hsm_service.generate(PID, recipient, SCOPE)

    local_service = ReversiblePseudonymService(KnownKeys(b"unused"), versions())
    assert local_service.reverse(from_hsm.value, recipient).personal_id == PID
    assert local_service.generate(PID, recipient, SCOPE) == from_hsm
