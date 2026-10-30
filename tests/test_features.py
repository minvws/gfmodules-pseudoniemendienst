import pytest

from app.config import Config, get_config
from app.features import FEATURES, enabled_features


def _config(**flags: bool) -> Config:
    """Flags are named ``<section>__<field>``, e.g. ``app__enable_test_routes``."""
    config = get_config().model_copy(deep=True)
    for name, value in flags.items():
        section, field = name.split("__")
        setattr(getattr(config, section), field, value)
    return config


def _ids(config: Config) -> list[str]:
    return [feature.id for feature in enabled_features(config)]


def test_oprf_is_always_enabled() -> None:
    config = _config(
        app__enable_exchange_services_routes=False,
        app__enable_saml_exchange_routes=False,
        jwt_signing__enabled=False,
        app__enable_test_routes=False,
    )

    assert _ids(config) == ["oprf"]


def test_all_features_enabled() -> None:
    config = _config(
        app__enable_exchange_services_routes=True,
        app__enable_saml_exchange_routes=True,
        jwt_signing__enabled=True,
        app__enable_test_routes=True,
    )

    assert _ids(config) == [feature.info.id for feature in FEATURES]


@pytest.mark.parametrize(
    ("flag", "feature_id"),
    [
        ("app__enable_exchange_services_routes", "reversible_pseudonym"),
        ("app__enable_exchange_services_routes", "irreversible_pseudonym"),
        ("app__enable_exchange_services_routes", "personal_id"),
        ("app__enable_saml_exchange_routes", "saml_exchange"),
        ("jwt_signing__enabled", "jwt_signing"),
        ("app__enable_test_routes", "test_routes"),
    ],
)
def test_feature_follows_config_flag(flag: str, feature_id: str) -> None:
    assert feature_id in _ids(_config(**{flag: True}))
    assert feature_id not in _ids(_config(**{flag: False}))


def test_feature_ids_are_unique() -> None:
    ids = [feature.info.id for feature in FEATURES]

    assert len(ids) == len(set(ids))
