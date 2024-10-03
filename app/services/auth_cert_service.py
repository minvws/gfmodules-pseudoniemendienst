import json
from enum import Enum

from asn1crypto.core import Asn1Value
from cryptography import x509
from pydantic import BaseModel

from app.services.tls_service import TLSService, CertAuthentications, CertAuthentication


class AuthRole(str, Enum):
    VAD = "VAD"
    DVA = "DVA"
    NZA = "NZA"
    ZA = "ZA"

class AuthEntry(BaseModel):
    hostname: str
    role: AuthRole
    org_name: str
    org_id: str
    za_name: str


class AuthorizationException(Exception):
    pass

class AuthCertService:
    """
    This service will validate any incoming client certificate and authorize it based on the provided allow list.
    It will set the authorized_id and authorized_role if the certificate is valid and authorized.
    """
    def __init__(self, path: str, tls_service: TLSService):
        self.tls_service = tls_service

        self.entries = self.load_entries(path)
        self.authorized_id: str|None = None
        self.authorized_role: AuthRole|None = None
        self.certificate_type: CertAuthentication|None = None

    def authorize(self, pem_cert: bytes) -> None:
        self.certificate_type = self.tls_service.get_certificate_type(pem_cert)

        if not self.tls_service.validate_cert(pem_cert):
            raise AuthorizationException("Provided client certificate is not valid")

        if self.certificate_type == CertAuthentications.AUTH_UZI_CERT:
            # Uzi certs are always ZA, and we extract the URA number from them
            self.authorized_role = AuthRole.ZA
            self.authorized_id = self.extract_ura_from_uzi_cert(pem_cert)
        else:
            # Any other cert type will be authorized based on the allow list
            if not self._authorize_cert(pem_cert):
                raise AuthorizationException("Provided client certificate is not authorized")

    def _authorize_cert(self, pem_cert: bytes) -> bool:
        cert = x509.load_pem_x509_certificate(pem_cert)
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

        for entry in self.entries:
            if entry.hostname == cn:
                self.authorized_id = entry.org_id
                self.authorized_role = entry.role
                return True

        raise AuthorizationException("No matching certificate found in allow list")

    def get_authorized_role(self) -> AuthRole:
        if self.get_authorized_id is None:
            raise AuthorizationException("No authorized id found. Please authorize first")
        return self.authorized_role # type: ignore

    def get_authorized_id(self) -> str:
        if self.get_authorized_id is None:
            raise AuthorizationException("No authorized id found. Please authorize first")
        return self.authorized_id # type: ignore

    def get_certificate_type(self) -> str:
        if self.certificate_type is None:
            raise AuthorizationException("No certificate type found. Please authorize first")
        return self.certificate_type

    @staticmethod
    def load_entries(path: str) -> list[AuthEntry]:
        with open(path, 'r') as f:
            data = json.load(f)

        entries = []
        for entry in data:
            entries.append(AuthEntry(**entry))
        return entries

    @staticmethod
    def extract_ura_from_uzi_cert(pem_cert: bytes) -> str:
        """
        Extract the URA number from a UZI certificate
        """
        cert = x509.load_pem_x509_certificate(pem_cert)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for entry in san.value.get_values_for_type(x509.OtherName):
            if entry.type_id == x509.ObjectIdentifier("2.5.5.5"):
                parts = Asn1Value.load(entry.value).native.split("-")
                if len(parts) == 7:
                    return "URA-" + str(parts[4])

        raise AuthorizationException("No URA number found in UZI certificate")

