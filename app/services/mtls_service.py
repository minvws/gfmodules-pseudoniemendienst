import logging
import textwrap

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException

from app.models.oin import Oin

logger = logging.getLogger(__name__)


class InvalidOinCertificate(HTTPException):
    def __init__(self, msg: str = "Invalid OIN Certificate") -> None:
        super().__init__(status_code=400, detail=msg)


class MtlsService:
    _CERT_START = "-----BEGIN CERTIFICATE-----"
    _CERT_END = "-----END CERTIFICATE-----"

    def _extract_client_cert(self, mtls_client_cert: str) -> bytes:
        return mtls_client_cert.split(",")[0].encode("ascii")

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

    def get_mtls_pub_key(
        self,
        mtls_client_cert: str,
    ) -> str:
        """
        Extract the public key from the client certificate
        """
        cert_bytes = self._extract_client_cert(mtls_client_cert)
        formatted_cert = self._enforce_cert_newlines(cert_bytes)
        cert = x509.load_pem_x509_certificate(formatted_cert.encode("ascii"))
        public_key = cert.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return public_pem.decode("ascii")

    def get_oin_cert(self, mtls_client_cert: str) -> x509.Certificate:
        try:
            cert_bytes = self._extract_client_cert(mtls_client_cert)
            cert_pem = self._enforce_cert_newlines(cert_bytes)
            return x509.load_pem_x509_certificate(cert_pem.encode())
        except ValueError as e:
            logger.warning(f"Unable to read certificate from header {e}")
            raise InvalidOinCertificate()

    def get_oin_from_cert(self, cert: x509.Certificate) -> Oin:
        attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)
        value = attr[0].value
        try:
            return Oin(value if isinstance(value, str) else value.decode())

        except ValueError as e:
            logger.warning(f"Invalid OIN in certificate {e}")
            raise InvalidOinCertificate()
