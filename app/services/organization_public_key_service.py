import json
from datetime import datetime, timedelta, timezone
from curses import raw
from re import A
from app.db.repositories.organization_public_key_repository import (
    OrganizationPublicKeyRepository,
)
from app.db.entities.organization_key import OrganizationPublicKey
from jwcrypto.jws import JWS, InvalidJWSSignature, InvalidJWSObject
from jwcrypto.jwk import JWK
import logging
import uuid
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.db import Database
from app.models.oin import Oin
from app.rid import RidUsage

logger = logging.getLogger(__name__)


class AlreadyExistsError(Exception):
    pass


class KeyNotFoundError(Exception):
    pass


def _normalize_scope(items: List[str]) -> List[str]:
    cleaned = [s.strip().lower() for s in items if s and s.strip()]
    return sorted(set(cleaned))


class OrganizationPublicKeyService:
    def __init__(self, db: Database):
        self.db = db

    def _validate_and_extract(self, raw_jws: str, org_id: Oin) -> JWK:
        jws = JWS()
        try:
            jws.deserialize(raw_jws)
        except InvalidJWSObject as ijo:
            raise Exception("TODO CUSTOM ERROR, Invalid jws")

        if "jwk" not in jws.jose_header and "JWK" not in jws.jose_header:
            raise Exception("TODO CUSTOM ERROR, MISSING JWK in header")

        private_components = ["d", "p", "q", "dp", "dq", "qi"]
        if any(p in jws.jose_header["jwk"] for p in private_components):
            raise Exception("TODO CUSTOM ERROR, JWK contains private key")

        jwk = JWK(**jws.jose_header.get("jwk", jws.jose_header.get("JWK")))
        try:
            jws.verify(jwk)
        except InvalidJWSSignature as ijs:
            raise Exception("TODO CUSTOM ERROR, Verification failed")
        try:
            payload = json.loads(jws.payload)
        except Exception as e:
            raise Exception("TODO CUSTOM ERROR, JSON decode error")
        if "iat" not in payload:
            raise Exception("TODO CUSTOM ERROR, iat not in payload")
        if "oin" not in payload:
            raise Exception("TODO CUSTOM ERROR, Missing 'oin' in jws")
        if datetime.fromtimestamp(payload["iat"], tz=timezone.utc) + timedelta(
            hours=1
        ) < datetime.now(tz=timezone.utc):
            raise Exception("TODO CUSTOM ERROR, jws to old")
        if payload["oin"] != org_id.value:
            raise Exception("TODO CUSTOM ERROR, Unautorized for supplied `oin`")
        return jwk

    def create(
        self,
        org_id: Oin,
        domain: str,
        kid: str | None,
        raw_jws: str,
    ) -> OrganizationPublicKey:
        jwk = self._validate_and_extract(raw_jws, org_id)
        kid: str = kid or jwk.key_id or jwk.thumbprint()

        with self.db.get_db_session() as session:
            try:
                repository = session.get_repository(OrganizationPublicKeyRepository)
                organization_public_key = OrganizationPublicKey(
                    organization_id=org_id,
                    domain=domain,
                    jwk=jwk.export(private_key=False, as_dict=False),
                    kid=kid,
                )
                repository.create(organization_public_key)
            except Exception as e:
                logger.exception(
                    "failed to create key entry for org %s and scope %r",
                    org_id,
                    domain,
                )
                # TODO:GB: Valid raise
                raise e
            session.commit()
            return organization_public_key

    def update(
        self,
        id: uuid.UUID,
        org_id: Oin,
        domain: str,
        kid: str | None,
        raw_jws: str,
    ) -> OrganizationPublicKey:
        jwk = self._validate_and_extract(raw_jws, org_id)
        kid: str = kid or jwk.key_id or jwk.thumbprint()

        with self.db.get_db_session() as session:
            try:
                repository = session.get_repository(OrganizationPublicKeyRepository)
                organization_public_key = repository.get(id)
                if not organization_public_key:
                    raise KeyNotFoundError()
                organization_public_key.domain = domain
                organization_public_key.jwk = jwk.export(
                    private_key=False, as_dict=False
                )
                organization_public_key.kid = kid
            except Exception as e:
                logger.exception(
                    "failed to create key entry for org %s and scope %r",
                    org_id,
                    domain,
                )
                # TODO:GB: Valid raise
                raise e
            session.commit()
            return organization_public_key

    def get_by_id(self, key_id: uuid.UUID) -> OrganizationPublicKey | None:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationPublicKeyRepository).get_by_id(
                key_id
            )
        return entry

    def get_by_org(self, org_id: Oin) -> List[OrganizationPublicKey]:
        with self.db.get_db_session() as session:
            return session.get_repository(OrganizationPublicKeyRepository).get_by_org(
                org_id
            )

    def get_by_org_and_domain(
        self, org_id: Oin, domain: str
    ) -> OrganizationPublicKey | None:
        with self.db.get_db_session() as session:
            return session.get_repository(
                OrganizationPublicKeyRepository
            ).get_by_org_and_domain(org_id, domain)

    def delete(self, key_id: uuid.UUID, organization_id: Oin) -> bool:
        with self.db.get_db_session() as session:
            repository = session.get_repository(OrganizationPublicKeyRepository)
            deleted = repository.delete(key_id, organization_id)
            if not deleted:
                entry = repository.get_by_id(key_id)
                if entry is not None and entry.organization_id != organization_id:
                    logger.warning(
                        "caller org %s attempted to delete key %s owned by org %s",
                        organization_id,
                        key_id,
                        entry.organization_id,
                    )

                return False

            session.commit()
            return True
