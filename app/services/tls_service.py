from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from starlette.requests import Request

from app.config import get_config

class CertAuthentication(str):
    pass

class CertAuthentications:
    AUTH_UZI_CERT = CertAuthentication("uzi_server")
    AUTH_OV_CERT = CertAuthentication("ov")
    AUTH_EV_CERT = CertAuthentication("ev")
    AUTH_ALL = CertAuthentication("*")


class CertAuthenticationException(Exception):
    pass


class TLSService:
    def get_certificate_type(self, request: Request) -> CertAuthentication:
        client_cert = request.headers.get("ssl_client_cert", None)

        # If the client certificate is not provided in the header, check if an override certificate is provided
        override_cert = get_config().app.auth_override_cert
        if override_cert is not None:
            with open(override_cert, "r") as file:
                client_cert = file.read()

        if client_cert is None:
            raise CertAuthenticationException("No client certificate provided")

        cert_type = self._detect_type(client_cert)
        if cert_type is None:
            raise CertAuthenticationException("Invalid client certificate provided")

        return cert_type

    @staticmethod
    def _detect_type(pem_data: str) -> CertAuthentication|None:
        """
        Get the certificate type (OV, EV, UZI) from the certificate. Note that this is a crude check and doesn't
        imply that the certificate is actually valid.
        """
        cert = x509.load_pem_x509_certificate(pem_data.encode())

        try:
            cert_policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            for info in cert_policies.value:
                if info.policy_identifier == x509.ObjectIdentifier("2.23.140.1.2.2"):
                    return CertAuthentications.AUTH_OV_CERT
                if info.policy_identifier == x509.ObjectIdentifier("2.23.140.1.1"):
                    return CertAuthentications.AUTH_EV_CERT
                if info.policy_identifier == x509.ObjectIdentifier("2.16.528.1.1003.1.2.8.6"):
                    return CertAuthentications.AUTH_UZI_CERT
        except x509.ExtensionNotFound:
            pass

        return None