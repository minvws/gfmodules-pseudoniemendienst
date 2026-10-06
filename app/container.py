import logging

import inject

from app.config import get_config
from app.db.db import Database
from app.services.auth.header import AuthHeaderService
from app.services.authorization_service import AuthorizationService
from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.irreversible.service import IrreversiblePseudonymService
from app.services.key_operations import build_key_operations
from app.services.oprf.oprf_service import OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversiblePseudonymService
from app.services.saml.client import SamlServiceClient

logger = logging.getLogger(__name__)


def container_config(binder: inject.Binder) -> None:
    config = get_config()

    db = Database(config_database=config.database)
    binder.bind(Database, db)

    organization_public_key_service = OrganizationPublicKeyService(db)
    binder.bind(OrganizationPublicKeyService, organization_public_key_service)

    authorization_service = AuthorizationService(db)
    binder.bind(AuthorizationService, authorization_service)

    hsm_key_version_service = HsmKeyVersionService(db)
    binder.bind(HsmKeyVersionService, hsm_key_version_service)

    hsm_key_cleanup_service = HsmKeyCleanupService(
        config.hsm,
        hsm_key_version_service,
    )
    binder.bind(HsmKeyCleanupService, hsm_key_cleanup_service)

    auth_header_service = AuthHeaderService(
        expected_audiences=config.authorization_headers.expected_audiences
    )
    binder.bind(AuthHeaderService, auth_header_service)

    key_operations = build_key_operations(config, hsm_key_version_service)

    oprf_service = OprfService(key_operations.oprf_evaluator)
    binder.bind(OprfService, oprf_service)

    reversible_pseudonym_service = ReversiblePseudonymService(
        key_operations.reversible_keys, hsm_key_version_service
    )
    binder.bind(ReversiblePseudonymService, reversible_pseudonym_service)

    irreversible_pseudonym_service = IrreversiblePseudonymService(
        key_operations.irreversible_keys, hsm_key_version_service
    )
    binder.bind(IrreversiblePseudonymService, irreversible_pseudonym_service)

    if config.app.enable_saml_exchange_routes:
        # Config.validate_saml_service_configured() guarantees this.
        assert config.saml_service.url is not None
        saml_service_client = SamlServiceClient(
            url=config.saml_service.url,
            timeout=config.saml_service.timeout,
            cert_file=config.saml_service.cert_file,
            key_file=config.saml_service.key_file,
            ca_cert_file=config.saml_service.ca_cert_file,
        )
        binder.bind(SamlServiceClient, saml_service_client)


def get_organization_public_key_service() -> OrganizationPublicKeyService:
    return inject.instance(OrganizationPublicKeyService)


def get_authorization_service() -> AuthorizationService:
    return inject.instance(AuthorizationService)


def get_reversible_pseudonym_service() -> ReversiblePseudonymService:
    return inject.instance(ReversiblePseudonymService)


def get_irreversible_pseudonym_service() -> IrreversiblePseudonymService:
    return inject.instance(IrreversiblePseudonymService)


def get_oprf_service() -> OprfService:
    return inject.instance(OprfService)


def get_database() -> Database:
    return inject.instance(Database)


def get_hsm_key_version_service() -> HsmKeyVersionService:
    return inject.instance(HsmKeyVersionService)


def get_hsm_key_cleanup_service() -> HsmKeyCleanupService:
    return inject.instance(HsmKeyCleanupService)


def get_auth_headers_service() -> AuthHeaderService:
    return inject.instance(AuthHeaderService)


def get_saml_service_client() -> SamlServiceClient:
    return inject.instance(SamlServiceClient)


if not inject.is_configured():
    inject.configure(container_config)
