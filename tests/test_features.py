import pytest

from app.config import Config, get_config
from app.features import FEATURES, enabled_features


def _config(**app_flags: bool) -> Config:
    config = get_config().model_copy(deep=True)
    for name, value in app_flags.items():
        setattr(config.app, name, value)
    return config


def _ids(config: Config) -> list[str]:
    return [feature.id for feature in enabled_features(config)]


def test_oprf_is_always_enabled() -> None:
    config = _config(
        enable_exchange_services_routes=False,
        enable_saml_exchange_routes=False,
        enable_test_routes=False,
    )

    assert _ids(config) == ["oprf"]


def test_all_features_enabled() -> None:
    config = _config(
        enable_exchange_services_routes=True,
        enable_saml_exchange_routes=True,
        enable_test_routes=True,
    )

    assert _ids(config) == [feature.info.id for feature in FEATURES]


@pytest.mark.parametrize(
    ("flag", "feature_id"),
    [
        ("enable_exchange_services_routes", "reversible_pseudonym"),
        ("enable_saml_exchange_routes", "saml_exchange"),
        ("enable_test_routes", "test_routes"),
    ],
)
def test_feature_follows_config_flag(flag: str, feature_id: str) -> None:
    assert feature_id in _ids(_config(**{flag: True}))
    assert feature_id not in _ids(_config(**{flag: False}))


def test_feature_ids_are_unique() -> None:
    ids = [feature.info.id for feature in FEATURES]

    assert len(ids) == len(set(ids))
