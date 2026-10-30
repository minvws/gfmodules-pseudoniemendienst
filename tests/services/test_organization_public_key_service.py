import uuid

import pytest

from app.db.models import OrganizationEntity
from app.db.models.organization_public_key import OrganizationPublicKeyEntity
from app.db.session import DbSession
from app.exceptions.access import OrganizationNotRegisteredError, RecipientNotFoundError
from app.exceptions.registration import (
    DomainAlreadyRegisteredError,
    DomainNotRegisteredError,
    InvalidJwsError,
    PublicKeyNotFoundError,
)
from app.models.oin import Oin
from app.services.organization_public_key_service import OrganizationPublicKeyService
from tests.conftest import create_signed_jws, generate_rsa_keypair, setup_org_and_key


def test_create_should_succeed(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:
    private_key_pem, _ = generate_rsa_keypair()
    raw_jws = create_signed_jws(private_key_pem, persisted_organization.external_id)

    result = organization_public_key_service.create(
        org_id=persisted_organization.external_id,
        domains=["test_domain"],
        raw_jws=raw_jws,
    )

    assert "id" in result
    assert "jwk" in result
    assert "domains" in result
    assert result["domains"] == ["test_domain"]


def test_create_should_raise_when_org_not_registered(
    organization_public_key_service: OrganizationPublicKeyService,
    valid_organization_id_2: Oin,
) -> None:
    private_key_pem, _ = generate_rsa_keypair()
    raw_jws = create_signed_jws(private_key_pem, valid_organization_id_2)

    with pytest.raises(OrganizationNotRegisteredError):
        organization_public_key_service.create(
            org_id=valid_organization_id_2,
            domains=["test_domain"],
            raw_jws=raw_jws,
        )


def test_create_should_raise_when_domain_already_registered(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:

    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["test_domain"],
    )

    private_key_pem, _ = generate_rsa_keypair()
    raw_jws = create_signed_jws(private_key_pem, persisted_organization.external_id)

    with pytest.raises(DomainAlreadyRegisteredError):
        organization_public_key_service.create(
            org_id=persisted_organization.external_id,
            domains=["test_domain"],
            raw_jws=raw_jws,
        )


def test_create_should_raise_when_jws_invalid(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    with pytest.raises(InvalidJwsError):
        organization_public_key_service.create(
            org_id=persisted_organization.external_id,
            domains=["test_domain"],
            raw_jws="invalid_jws",
        )


def test_update_should_succeed(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
    db_session: DbSession,
) -> None:

    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["domain1"],
    )

    keys = organization_public_key_service.get_by_org(
        persisted_organization.external_id
    )
    key_id = uuid.UUID(keys[0]["id"])

    new_private_key_pem, _ = generate_rsa_keypair()
    raw_jws = create_signed_jws(new_private_key_pem, persisted_organization.external_id)

    result = organization_public_key_service.update(
        id=key_id,
        org_id=persisted_organization.external_id,
        domains=["domain2"],
        raw_jws=raw_jws,
    )

    assert result["id"] == str(key_id)
    assert result["domains"] == ["domain2"]


def test_update_should_raise_when_org_not_registered(
    organization_public_key_service: OrganizationPublicKeyService,
    valid_organization_id_2: Oin,
) -> None:
    private_key_pem, _ = generate_rsa_keypair()
    raw_jws = create_signed_jws(private_key_pem, valid_organization_id_2)

    with pytest.raises(OrganizationNotRegisteredError):
        organization_public_key_service.update(
            id=uuid.uuid4(),
            org_id=valid_organization_id_2,
            domains=["test_domain"],
            raw_jws=raw_jws,
        )


def test_update_should_raise_when_key_not_found(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    private_key_pem, _ = generate_rsa_keypair()
    raw_jws = create_signed_jws(private_key_pem, persisted_organization.external_id)

    with pytest.raises(PublicKeyNotFoundError):
        organization_public_key_service.update(
            id=uuid.uuid4(),
            org_id=persisted_organization.external_id,
            domains=["test_domain"],
            raw_jws=raw_jws,
        )


def test_update_should_raise_when_domain_already_registered(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["domain1"],
    )
    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["domain2"],
    )

    keys = organization_public_key_service.get_by_org(
        persisted_organization.external_id
    )
    key_id = uuid.UUID(keys[0]["id"])

    new_private_key_pem, _ = generate_rsa_keypair()
    raw_jws = create_signed_jws(new_private_key_pem, persisted_organization.external_id)

    with pytest.raises(DomainAlreadyRegisteredError):
        organization_public_key_service.update(
            id=key_id,
            org_id=persisted_organization.external_id,
            domains=["domain2"],
            raw_jws=raw_jws,
        )


def test_update_should_raise_when_jws_invalid(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["domain1"],
    )

    keys = organization_public_key_service.get_by_org(
        persisted_organization.external_id
    )
    key_id = uuid.UUID(keys[0]["id"])

    with pytest.raises(InvalidJwsError):
        organization_public_key_service.update(
            id=key_id,
            org_id=persisted_organization.external_id,
            domains=["domain2"],
            raw_jws="invalid_jws",
        )


def test_get_by_id_should_return_key_when_exists(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["test_domain"],
    )

    keys = organization_public_key_service.get_by_org(
        persisted_organization.external_id
    )
    key_id = uuid.UUID(keys[0]["id"])

    result = organization_public_key_service.get_by_id(key_id)

    assert result is not None
    assert result.id == key_id


def test_get_by_id_should_return_none_when_not_exists(
    organization_public_key_service: OrganizationPublicKeyService,
) -> None:
    result = organization_public_key_service.get_by_id(uuid.uuid4())
    assert result is None


def test_get_by_org_should_return_keys(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["domain1"],
    )
    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["domain2"],
    )

    result = organization_public_key_service.get_by_org(
        persisted_organization.external_id
    )

    assert len(result) == 2
    assert result[0]["domains"] == ["domain1"]
    assert result[1]["domains"] == ["domain2"]


def test_get_by_org_should_raise_when_org_not_registered(
    organization_public_key_service: OrganizationPublicKeyService,
    valid_organization_id_2: Oin,
) -> None:
    with pytest.raises(OrganizationNotRegisteredError):
        organization_public_key_service.get_by_org(valid_organization_id_2)


def test_get_by_org_should_return_empty_list(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    result = organization_public_key_service.get_by_org(
        persisted_organization.external_id
    )
    assert result == []


def test_get_by_org_and_domain_should_return_key_when_domain_matches(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["test_domain"],
    )

    result = organization_public_key_service.get_by_org_and_domain(
        persisted_organization.external_id, "test_domain"
    )

    assert isinstance(result, OrganizationPublicKeyEntity)
    assert "test_domain" in result.domains


def test_get_by_org_and_domain_should_return_key_when_wildcard_matches(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["*"],
    )

    result = organization_public_key_service.get_by_org_and_domain(
        persisted_organization.external_id, "test_domain"
    )

    assert isinstance(result, OrganizationPublicKeyEntity)
    assert "*" in result.domains


def test_get_by_org_and_domain_should_raise_when_org_not_found(
    organization_public_key_service: OrganizationPublicKeyService,
    valid_organization_id_2: Oin,
) -> None:
    with pytest.raises(RecipientNotFoundError):
        organization_public_key_service.get_by_org_and_domain(
            valid_organization_id_2, "test_domain"
        )


def test_get_by_org_and_domain_should_raise_when_domain_not_registered(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    with pytest.raises(DomainNotRegisteredError):
        organization_public_key_service.get_by_org_and_domain(
            persisted_organization.external_id, "unregistered_domain"
        )


def test_delete_should_succeed(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    setup_org_and_key(
        organization_public_key_service,
        persisted_organization,
        domains=["test_domain"],
    )

    keys = organization_public_key_service.get_by_org(
        persisted_organization.external_id
    )
    key_id = uuid.UUID(keys[0]["id"])

    organization_public_key_service.delete(key_id, persisted_organization.external_id)

    result = organization_public_key_service.get_by_id(key_id)
    assert result is None


def test_delete_should_raise_when_org_not_registered(
    organization_public_key_service: OrganizationPublicKeyService,
    valid_organization_id_2: Oin,
) -> None:
    with pytest.raises(OrganizationNotRegisteredError):
        organization_public_key_service.delete(uuid.uuid4(), valid_organization_id_2)


def test_delete_should_raise_when_key_not_found(
    organization_public_key_service: OrganizationPublicKeyService,
    persisted_organization: OrganizationEntity,
) -> None:
    with pytest.raises(PublicKeyNotFoundError):
        organization_public_key_service.delete(
            uuid.uuid4(), persisted_organization.external_id
        )
