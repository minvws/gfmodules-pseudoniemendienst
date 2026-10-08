from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel

from app.config import Config


class FeatureInfo(BaseModel):
    id: str
    title: str
    description: str


@dataclass(frozen=True)
class Feature:
    info: FeatureInfo
    enabled: Callable[[Config], bool]


FEATURES: list[Feature] = [
    Feature(
        info=FeatureInfo(
            id="oprf",
            title="OPRF",
            description="Pseudonyms via a blinded OPRF evaluation",
        ),
        enabled=lambda _: True,
    ),
    Feature(
        info=FeatureInfo(
            id="reversible_pseudonym",
            title="Reversible pseudonym",
            description="Exchange a personal ID for a reversible pseudonym",
        ),
        enabled=lambda config: config.app.enable_exchange_services_routes,
    ),
    Feature(
        info=FeatureInfo(
            id="irreversible_pseudonym",
            title="Irreversible pseudonym",
            description=(
                "Exchange a personal ID, or a reversible pseudonym issued to "
                "the caller, for an irreversible pseudonym"
            ),
        ),
        enabled=lambda config: config.app.enable_exchange_services_routes,
    ),
    Feature(
        info=FeatureInfo(
            id="saml_exchange",
            title="SAML exchange (mock)",
            description="Exchange a DigiD SAML response for a pseudonym",
        ),
        enabled=lambda config: config.app.enable_saml_exchange_routes,
    ),
    Feature(
        info=FeatureInfo(
            id="test_routes",
            title="OPRF test endpoints",
            description="Helper endpoints for testing the OPRF and JWE flows",
        ),
        enabled=lambda config: config.app.enable_test_routes,
    ),
]


def enabled_features(config: Config) -> list[FeatureInfo]:
    return [feature.info for feature in FEATURES if feature.enabled(config)]
