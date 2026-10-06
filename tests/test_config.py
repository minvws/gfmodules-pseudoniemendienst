import base64
import secrets
from pathlib import Path

import pytest
from pydantic import SecretStr

from app.config import ConfigOprf, ConfigPseudonym


def test_load_master_key_rejects_empty() -> None:
    with pytest.raises(ValueError, match="not configured"):
        ConfigPseudonym(master_key=SecretStr("")).load_master_key()


def test_load_master_key_rejects_short() -> None:
    short = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii")
    with pytest.raises(ValueError, match="too short"):
        ConfigPseudonym(master_key=SecretStr(short)).load_master_key()


def test_load_master_key_accepts_valid_key() -> None:
    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    key = ConfigPseudonym(master_key=SecretStr(raw)).load_master_key()
    assert len(key) == 32


def test_load_server_key_rejects_missing_file(tmp_path: Path) -> None:
    config = ConfigOprf(server_key_file=str(tmp_path / "does-not-exist.key"))
    with pytest.raises(FileNotFoundError, match="not found"):
        config.load_server_key()


def test_load_server_key_rejects_empty_file(tmp_path: Path) -> None:
    key_file = tmp_path / "server.key"
    key_file.write_text("")
    config = ConfigOprf(server_key_file=str(key_file))
    with pytest.raises(ValueError, match="empty"):
        config.load_server_key()


def test_load_server_key_accepts_valid_file(tmp_path: Path) -> None:
    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    key_file = tmp_path / "server.key"
    key_file.write_text(raw)
    config = ConfigOprf(server_key_file=str(key_file))

    assert config.load_server_key() == base64.urlsafe_b64decode(raw)
