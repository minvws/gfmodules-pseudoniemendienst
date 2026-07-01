import base64
import secrets

import pytest

from app.container import _load_master_key


def test_load_master_key_rejects_empty() -> None:
    with pytest.raises(ValueError, match="not configured"):
        _load_master_key("")


def test_load_master_key_rejects_short() -> None:
    short = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii")
    with pytest.raises(ValueError, match="too short"):
        _load_master_key(short)


def test_load_master_key_accepts_valid_key() -> None:
    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    key = _load_master_key(raw)
    assert len(key) == 32
