import textwrap

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from starlette.requests import Request
from uzireader.uziserver import UziServer
import logging

from app.db.entities.organization import Organization
from app.services.org_service import OrgService

logger = logging.getLogger(__name__)


class MtlsService:
    _CERT_START = "-----BEGIN CERTIFICATE-----"
    _CERT_END = "-----END CERTIFICATE-----"
    _SSL_CLIENT_CERT_HEADER_NAME = "X-Forwarded-Tls-Client-Cert"

    def __init__(
        self,
        override_cert: str | None,
        org_service: OrgService,
    ) -> None:
        self.__cert: bytes | None = None
        self.org_service = org_service

        if override_cert is not None and override_cert != "":
            with open(override_cert, "r") as f:
                override_cert = f.read().strip()
            self.__cert = override_cert.encode("ascii")

    def _enforce_cert_newlines(self, cert_bytes: bytes) -> str:
        cert_data = (
            cert_bytes.decode("ascii")
            .split(self._CERT_START)[-1]
            .split(self._CERT_END)[0]
            .strip()
        )
        result = self._CERT_START
        result += "\n"
        result += "\n".join(textwrap.wrap(cert_data.replace(" ", ""), 64))
        result += "\n"
        result += self._CERT_END

        return result

    def get_mtls_cert(self, request: Request) -> bytes:
        """
        Returns the MTLS cert found in the request, or returns the override certificate if set
        """
        if self.__cert:
            return self.__cert

        if self._SSL_CLIENT_CERT_HEADER_NAME not in request.headers:
            logger.error(
                f"MTLS certificate {self._SSL_CLIENT_CERT_HEADER_NAME} header missing in request"
            )
            raise HTTPException(
                status_code=401,
                detail="Missing client certificate",
            )
        print(request.headers[self._SSL_CLIENT_CERT_HEADER_NAME])
        return request.headers[self._SSL_CLIENT_CERT_HEADER_NAME].encode("ascii")

    def get_mtls_pub_key(self, request: Request) -> str:
        """
        Extract the public key from the client certificate
        """
        cert_bytes = self.get_mtls_cert(request)
        formatted_cert = self._enforce_cert_newlines(cert_bytes)
        print(formatted_cert)
        cert = x509.load_pem_x509_certificate(cert_bytes)
        public_key = cert.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return public_pem.decode("ascii")

    def get_mtls_uzi_data(self, request: Request) -> UziServer:
        """
        Extract UZI data from the client certificate
        """
        cert_bytes = self.get_mtls_cert(request)
        formatted_cert = self._enforce_cert_newlines(cert_bytes)
        return UziServer(verify="SUCCESS", cert=formatted_cert)

    def get_org_from_request(self, request: Request) -> Organization:
        """
        Extract the organization from the client certificate in the request
        """

        data = self.get_mtls_uzi_data(request)
        if data["CardType"] != "S":
            raise HTTPException(
                status_code=401,
                detail="Invalid client certificate. Need an UZI S-type certificate.",
            )

        ura = data["SubscriberNumber"]
        org = self.org_service.get_by_ura(ura)
        if org is None:
            raise HTTPException(
                status_code=404, detail=f"organization for URA {ura} is not registered"
            )

        return org
