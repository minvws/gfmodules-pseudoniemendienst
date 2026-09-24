import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import gfmodules.logging as gflog
from jwcrypto.common import base64url_decode
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSObject, InvalidJWSSignature

from app.db.db import Database
from app.db.models.organization_public_key import OrganizationPublicKeyEntity
from app.db.repositories.organization_public_key_repository import (
    OrganizationPublicKeyRepository,
)
from app.db.repositories.organization_repository import OrganizationRepository
from app.exceptions import (
    DomainAlreadyRegisteredError,
    DomainNotRegisteredError,
    InvalidJwsError,
    OrganizationNotRegisteredError,
    PublicKeyNotFoundError,
    RecipientNotFoundError,
)
from app.logging.events import Log
from app.models.oin import Oin
from app.utils.datetime import now_utc

logger = logging.getLogger(__name__)

_CURVE_BITS = {
    "P-256": 256,
    "P-384": 384,
    "P-521": 521,
    "secp256k1": 256,
    "Ed25519": 256,
    "Ed448": 448,
    "X25519": 256,
    "X448": 448,
}


def _key_algorithm(jwk: dict[str, Any]) -> str | None:
    """Describes the public key type without exposing any key material."""
    kty = jwk.get("kty")
    crv = jwk.get("crv")
    if kty in ("EC", "OKP") and crv:
        return f"{kty}/{crv}"
    return kty if isinstance(kty, str) else None


def _key_length(jwk: dict[str, Any]) -> int | None:
    if jwk.get("kty") == "RSA" and isinstance(jwk.get("n"), str):
        try:
            return int.from_bytes(base64url_decode(jwk["n"]), "big").bit_length()
        except ValueError:
            return None
    return _CURVE_BITS.get(jwk.get("crv", ""))


def _log_rejected(org_id: Oin, key_algoritme: str | None, reason: str) -> None:
    # PRS-KEY-006
    gflog.emit(
        logger,
        Log.DECRYPT_PUBKEY_REJECTED,
        "decryption public key registration refused",
        fields={
            "organisatie_oin": org_id.value,
            "key_algoritme": key_algoritme,
            "rejection_reason": reason,
        },
        stacklevel=2,
    )


def _log_registered(org_id: Oin, jwk: dict[str, Any]) -> None:
    # PRS-KEY-005. Decryption keys are not numbered; the organisation-supplied
    # kid is the identifier that tells key generations apart.
    gflog.emit(
        logger,
        Log.DECRYPT_PUBKEY_REGISTERED,
        "decryption public key registered",
        fields={
            "organisatie_oin": org_id.value,
            "key_algoritme": _key_algorithm(jwk),
            "key_lengte": _key_length(jwk),
            "key_versie": jwk.get("kid"),
        },
        stacklevel=2,
    )


class OrganizationPublicKeyService:
    def __init__(self, db: Database):
        self.db = db

    def _validate_and_extract(self, raw_jws: str, org_id: Oin) -> JWK:
        """
        Validates the self-signed JWS and returns the public key it carries.
        """
        key_algoritme: str | None = None
        try:
            jws = JWS.from_jose_token(raw_jws)
            if "jwk" in jws.jose_header and isinstance(jws.jose_header["jwk"], dict):
                key_algoritme = _key_algorithm(jws.jose_header["jwk"])
            return self._extract_verified_key(jws, org_id)
        except InvalidJWSObject:
            _log_rejected(org_id, key_algoritme, "JWS invalid")
            raise InvalidJwsError("JWS invalid")
        except InvalidJwsError as e:
            _log_rejected(org_id, key_algoritme, e.message)
            raise

    def _extract_verified_key(self, jws: JWS, org_id: Oin) -> JWK:
        if "jwk" not in jws.jose_header:
            raise InvalidJwsError("Missing 'jwk' in header")

        private_components = ["d", "p", "q", "dp", "dq", "qi"]
        if any(p in jws.jose_header["jwk"] for p in private_components):
            raise InvalidJwsError("'jwk' contains private components")
        if "kid" not in jws.jose_header["jwk"]:
            raise InvalidJwsError("'jwk' is missing an 'kid'")

        jwk = JWK(**jws.jose_header["jwk"])
        try:
            jws.verify(jwk)
        except InvalidJWSSignature:
            raise InvalidJwsError("Verification of jws failed")
        try:
            payload = json.loads(jws.payload)
        except Exception as e:
            raise InvalidJwsError("Unable to decode jws payload") from e
        if "iat" not in payload:
            raise InvalidJwsError("Missing 'iat' in payload")
        if "oin" not in payload:
            raise InvalidJwsError("Missing 'oin' in payload")
        if (
            datetime.fromtimestamp(payload["iat"], tz=timezone.utc) + timedelta(hours=1)
            < now_utc()
        ):
            raise InvalidJwsError("JWS expired")
        if payload["oin"] != org_id.value:
            raise InvalidJwsError("Unautorized for supplied `oin`")
        return jwk

    def create(
        self,
        org_id: Oin,
        domains: list[str],
        raw_jws: str,
    ) -> dict[str, Any]:
        jwk_dict = self._validate_and_extract(raw_jws, org_id).export(as_dict=True)
        with self.db.get_db_session(commit=True) as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(org_id)
            if org is None:
                # TODO GB: This can only happen when authorization is revoked but token is still valid.
                # For consistency we need to decide how to handle this throughout all apps
                raise OrganizationNotRegisteredError()

            domains_as_set = set(domains)
            key_with_same_domain = [
                pk
                for pk in org.public_keys
                if list(domains_as_set.intersection(pk.domains))
            ]
            if key_with_same_domain:
                _log_rejected(
                    org_id, _key_algorithm(jwk_dict), "domain already registered"
                )
                raise DomainAlreadyRegisteredError()
            public_key = OrganizationPublicKeyEntity(
                domains=domains,
                jwk=jwk_dict,
            )
            org.public_keys.append(public_key)
            session.flush()
            _log_registered(org_id, jwk_dict)
            return public_key.to_dict()

    def update(
        self,
        id: uuid.UUID,
        org_id: Oin,
        domains: list[str],
        raw_jws: str,
    ) -> dict[str, Any]:
        jwk_dict = self._validate_and_extract(raw_jws, org_id).export(as_dict=True)
        with self.db.get_db_session(commit=True) as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_registered(org_id)
            public_key_for_id = [pk for pk in org.public_keys if pk.id == id]

            domains_as_set = set(domains)
            if len(public_key_for_id) != 1:
                raise PublicKeyNotFoundError()
            key_with_same_domain = [
                pk
                for pk in org.public_keys
                if domains_as_set.intersection(pk.domains) and pk.id != id
            ]
            if key_with_same_domain:
                _log_rejected(
                    org_id, _key_algorithm(jwk_dict), "domain already registered"
                )
                raise DomainAlreadyRegisteredError()
            public_key = public_key_for_id[0]
            public_key.domains = domains
            public_key.jwk = jwk_dict
            _log_registered(org_id, jwk_dict)
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
            org = org_repo.get_registered(org_id)
            return [pk.to_dict() for pk in org.public_keys]

    def get_by_org_and_domain(
        self, org_id: Oin, domain: str
    ) -> OrganizationPublicKeyEntity:
        with self.db.get_db_session() as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_one_by_external_id(org_id)
            if not org:
                # The organization is the recipient of an exchange.
                raise RecipientNotFoundError()
            public_key = [pk for pk in org.public_keys if domain in pk.domains]
            if not public_key:
                public_key = [pk for pk in org.public_keys if "*" in pk.domains]
            if not public_key:
                raise DomainNotRegisteredError()
            return public_key[0]

    def delete(self, key_id: uuid.UUID, organization_id: Oin) -> bool:
        with self.db.get_db_session(commit=True) as session:
            org_repo = session.get_repository(OrganizationRepository)
            org = org_repo.get_registered(organization_id)
            return session.get_repository(OrganizationPublicKeyRepository).delete(
                key_id, org.id
            )
