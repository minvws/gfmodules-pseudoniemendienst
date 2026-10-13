import base64
import secrets
from unittest.mock import MagicMock

import pytest

from app.config import get_config
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.irreversible.keys import (
    HsmIrreversibleKeyOperations,
    LocalIrreversibleKeyOperations,
)
from app.services.key_operations import KeyOperations, _load_master_key
from app.services.oprf.evaluators import HsmOprfEvaluator, LocalOprfEvaluator
from app.services.reversible.keys import (
    HsmReversibleKeyOperations,
    LocalReversibleKeyOperations,
)


def _key_operations(**hsm: object) -> KeyOperations:
    config = get_config().model_copy(deep=True)
    config.hsm = config.hsm.model_copy(update=hsm)
    return KeyOperations.from_config(config, MagicMock(spec=HsmKeyVersionService))


def test_from_config_uses_local_keys_without_hsm_url() -> None:
    operations = _key_operations(url=None)

    assert isinstance(operations.oprf_evaluator, LocalOprfEvaluator)
    assert isinstance(operations.reversible_keys, LocalReversibleKeyOperations)
    assert isinstance(operations.irreversible_keys, LocalIrreversibleKeyOperations)


def test_from_config_uses_the_hsm_section() -> None:
    operations = _key_operations(
        url="https://hsm.local",
        module="utimaco",
        slot="slot3",
        timeout=2.5,
        cert_file="c",
        key_file="k",
        ca_cert_file="ca",
    )

    assert isinstance(operations.oprf_evaluator, HsmOprfEvaluator)
    assert isinstance(operations.reversible_keys, HsmReversibleKeyOperations)
    assert isinstance(operations.irreversible_keys, HsmIrreversibleKeyOperations)
    http = operations.reversible_keys._client._http
    assert http._endpoint == "https://hsm.local/hsm/utimaco/slot3"
    assert http._timeout == 2.5
    assert http._cert == ("c", "k")
    assert http._verify_ca == "ca"


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
