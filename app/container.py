import inject

from app.config import get_config
from app.db.db import Database
from app.services.auth.header import AuthHeaderService
from app.services.authorization_service import AuthorizationService
from app.services.hsm_key_cleanup_service import HsmKeyCleanupService
from app.services.hsm_key_version_service import HsmKeyVersionService
from app.services.http_client import HttpService
from app.services.irreversible.service import IrreversiblePseudonymService
from app.services.key_operations import KeyOperations
from app.services.oprf.oprf_service import OprfService
from app.services.organization_public_key_service import OrganizationPublicKeyService
from app.services.reversible.service import ReversiblePseudonymService
from app.services.saml.client import SamlServiceClient


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

    auth_header_service = AuthHeaderService(
        expected_audiences=config.authorization_headers.expected_audiences
    )
    binder.bind(AuthHeaderService, auth_header_service)

    key_operations = KeyOperations.from_config(config, hsm_key_version_service)

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

    hsm_key_cleanup_service = HsmKeyCleanupService(
        oprf_keys=key_operations.oprf_evaluator,
        irreversible_keys=key_operations.irreversible_keys,
        reversible_keys=key_operations.reversible_keys,
        version_service=hsm_key_version_service,
    )
    binder.bind(HsmKeyCleanupService, hsm_key_cleanup_service)

    if config.app.enable_saml_exchange_routes:
        if not config.saml_service.url:
            raise ValueError(
                "saml_service.url is not configured. It is required when "
                "enable_saml_exchange_routes is set."
            )
        saml_service_client = SamlServiceClient(
            HttpService(
                endpoint=config.saml_service.url,
                timeout=config.saml_service.timeout,
                mtls_cert=config.saml_service.cert_file,
                mtls_key=config.saml_service.key_file,
                verify_ca=config.saml_service.ca_cert_file or True,
            )
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
