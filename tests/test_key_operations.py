import base64
import secrets
from pathlib import Path

from pydantic import SecretStr

from app.config import (
    Config,
    ConfigApp,
    ConfigAuthorizationHeaders,
    ConfigDatabase,
    ConfigHsm,
    ConfigOprf,
    ConfigPseudonym,
    ConfigUvicorn,
)
from app.db.db import Database
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.irreversible.keys import (
    HsmIrreversibleKeyOperations,
    LocalIrreversibleKeyOperations,
)
from app.services.key_operations import build_key_operations
from app.services.oprf.evaluators import HsmOprfEvaluator, LocalOprfEvaluator
from app.services.reversible.keys import (
    HsmReversibleKeyOperations,
    LocalReversibleKeyOperations,
)


def _config(
    hsm: ConfigHsm | None = None,
    oprf: ConfigOprf | None = None,
    pseudonym: ConfigPseudonym | None = None,
) -> Config:
    return Config(
        app=ConfigApp(),
        database=ConfigDatabase(dsn=SecretStr("sqlite://")),
        uvicorn=ConfigUvicorn(),
        hsm=hsm or ConfigHsm(),
        oprf=oprf or ConfigOprf(),
        pseudonym=pseudonym or ConfigPseudonym(),
        authorization_headers=ConfigAuthorizationHeaders(expected_audiences=["aud"]),
    )


def test_build_key_operations_uses_hsm_backend_when_hsm_url_set(
    database: Database,
) -> None:
    config = _config(hsm=ConfigHsm(hsm_url="https://hsm.local"))

    result = build_key_operations(config, HsmKeyVersionService(database))

    assert isinstance(result.oprf_evaluator, HsmOprfEvaluator)
    assert isinstance(result.reversible_keys, HsmReversibleKeyOperations)
    assert isinstance(result.irreversible_keys, HsmIrreversibleKeyOperations)


def test_build_key_operations_uses_local_backend_when_hsm_url_not_set(
    database: Database, tmp_path: Path
) -> None:
    key_file = tmp_path / "server.key"
    key_file.write_text(
        base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    )
    config = _config(
        oprf=ConfigOprf(server_key_file=str(key_file)),
        pseudonym=ConfigPseudonym(
            master_key=SecretStr(
                base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
            )
        ),
    )

    result = build_key_operations(config, HsmKeyVersionService(database))

    assert isinstance(result.oprf_evaluator, LocalOprfEvaluator)
    assert isinstance(result.reversible_keys, LocalReversibleKeyOperations)
    assert isinstance(result.irreversible_keys, LocalIrreversibleKeyOperations)
