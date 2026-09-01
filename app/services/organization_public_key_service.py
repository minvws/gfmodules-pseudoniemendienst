from typing import Any
from fastapi import HTTPException
from app.db.models.organization_public_key import OrganizationPublicKeyEntity
from app.db.repositories.organization_repository import OrganizationRepository
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSObject, InvalidJWSSignature

from app.db.db import Database
from app.db.repositories.organization_public_key_repository import (
    OrganizationPublicKeyRepository,
)
from app.models.oin import Oin

logger = logging.getLogger(__name__)


class AlreadyExistsError(Exception):
    pass


class KeyNotFoundError(Exception):
    pass


def _normalize_scope(items: list[str]) -> list[str]:
    cleaned = [s.strip().lower() for s in items if s and s.strip()]
    return sorted(set(cleaned))


class OrganizationPublicKeyService:
    def __init__(self, db: Database):
        self.db = db

    def _validate_and_extract(self, raw_jws: str, org_id: Oin) -> JWK:
        jws = JWS()
        try:
            jws.deserialize(raw_jws)
        except InvalidJWSObject:
            raise Exception("TODO CUSTOM ERROR, Invalid jws")

        if "jwk" not in jws.jose_header and "JWK" not in jws.jose_header:
            raise Exception("TODO CUSTOM ERROR, MISSING JWK in header")

        private_components = ["d", "p", "q", "dp", "dq", "qi"]
        if any(p in jws.jose_header["jwk"] for p in private_components):
            raise Exception("TODO CUSTOM ERROR, JWK contains private key")
        if "kid" not in jws.jose_header["jwk"]:
            raise Exception("TODO CUSTOM ERROR, Missing 'kid' in jwk")

        jwk = JWK(**jws.jose_header.get("jwk", jws.jose_header.get("JWK")))
        try:
            jws.verify(jwk)
        except InvalidJWSSignature:
            raise Exception("TODO CUSTOM ERROR, Verification failed")
        try:
            payload = json.loads(jws.payload)
        except Exception:
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
        raw_jws: str,
    ) -> dict[str, Any]:
        jwk = self._validate_and_extract(raw_jws, org_id)
        with self.db.get_db_session(commit=True) as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(org_id)
            if org is None:
                raise HTTPException(
                    status_code=405, detail="Organization does not exist"
                )
            key_with_same_domain = [
                pk for pk in org.public_keys if domain in pk.domains
            ]
            if key_with_same_domain:
                raise Exception("Domain is already registered to different key")
            public_key = OrganizationPublicKeyEntity(
                domains=[domain],
                jwk=jwk.export(as_dict=True),
            )
            org.public_keys.append(
                OrganizationPublicKeyEntity(
                    domains=[domain],
                    jwk=jwk.export(as_dict=True),
                )
            )
            session.flush()
            return public_key.to_dict()

    def update(
        self,
        id: uuid.UUID,
        org_id: Oin,
        domain: str,
        raw_jws: str,
    ) -> dict[str, Any]:
        jwk = self._validate_and_extract(raw_jws, org_id)
        with self.db.get_db_session(commit=True) as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(org_id)
            if org is None:
                raise HTTPException(
                    status_code=405, detail="Organization does not exist"
                )
            public_key_for_id = [pk for pk in org.public_keys if pk.id == id]
            if len(public_key_for_id) != 1:
                raise HTTPException(status_code=404, detail="public key not found")
            key_with_same_domain = [
                pk for pk in org.public_keys if domain in pk.domains and pk.id != id
            ]
            if key_with_same_domain:
                raise Exception("Domain is already registered to different key")
            public_key = public_key_for_id[0]
            public_key.domains = [domain]
            public_key.jwk = jwk.export(as_dict=True)
            return public_key.to_dict()

    def get_by_id(self, key_id: uuid.UUID) -> OrganizationPublicKeyEntity | None:
        with self.db.get_db_session() as session:
            entry = session.get_repository(OrganizationPublicKeyRepository).get_by_id(
                key_id
            )
        return entry

    def get_by_org(self, org_id: Oin) -> list[dict[str, Any]]:
        with self.db.get_db_session() as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(org_id)
            if not org:
                raise HTTPException(
                    status_code=404, detail="Organization does not exist"
                )
            return [pk.to_dict() for pk in org.public_keys]

    def get_by_org_and_domain(
        self, org_id: Oin, domain: str
    ) -> OrganizationPublicKeyEntity:
        with self.db.get_db_session() as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(org_id)
            if not org:
                raise HTTPException(
                    status_code=404, detail="Organization does not exist"
                )
            public_key = [pk for pk in org.public_keys if domain in pk.domains]
            if not public_key:
                public_key = [pk for pk in org.public_keys if "*" in pk.domains]
            if not public_key:
                raise Exception("TODO NICE EXCEPTION, Recipient not found")
            return public_key[0]

    def delete(self, key_id: uuid.UUID, organization_id: Oin) -> bool:
        with self.db.get_db_session(commit=True) as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(organization_id)
            if not org:
                raise HTTPException(
                    status_code=404, detail="Organization does not exist"
                )
            org.public_keys = [pk for pk in org.public_keys if pk.id != key_id]
        return True
