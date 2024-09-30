from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448
from cryptography.x509 import Certificate
from cryptography.x509.oid import ExtensionOID
import validators


class CertAuthentication(str):
    pass

class CertAuthentications:
    AUTH_UZI_CERT = CertAuthentication("uzi_server")
    AUTH_OV_CERT = CertAuthentication("ov")
    AUTH_EV_CERT = CertAuthentication("ev")
    AUTH_ALL = CertAuthentication("*")


class CertAuthenticationException(Exception):
    pass

class CertValidationException(Exception):
    pass

class TLSService:
    def __init__(self, curves: str, min_bit_size: int = 2048):
        self.min_bit_size = min_bit_size
        self.curves = [item.strip() for item in curves.split(",")]

    def get_certificate_type(self, pem: bytes) -> CertAuthentication:
        """
        Get the certificate type (OV, EV, UZI) from the certificate.
        """
        cert_type = self._detect_type(pem)
        if cert_type is None:
            raise CertAuthenticationException("Invalid client certificate provided")

        return cert_type

    def validate_cert(self, pem: bytes) -> bool:
        """
        Validate the certificate (EV, OV, and UZI). Note that general validity (issues, CA, expiration etc.) are already
        checked by the server. We check some additional data that is specific for our application.
        """
        try:
            cert = x509.load_pem_x509_certificate(pem)
            return self.validate_cert_elements(cert)
        except ValueError:
            return False

    def validate_cert_elements(self, cert: Certificate) -> bool:
        if isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
            curve_name = cert.public_key().curve.name       # type: ignore
            if curve_name not in self.curves:
                raise CertValidationException(f"Curve {curve_name} is not allowed")
        elif isinstance(cert.public_key(), ed25519.Ed25519PublicKey):
            pass
        elif isinstance(cert.public_key(), ed448.Ed448PublicKey):
            pass
        elif isinstance(cert.public_key(), rsa.RSAPublicKey):
            if cert.public_key().key_size < self.min_bit_size:      # type: ignore
                raise CertValidationException(f"RSA key size is too small: {cert.public_key().key_size}") # type: ignore
        else:
            raise CertValidationException("Invalid key type")

        # No wildcards in CN are allowed
        subject = cert.subject
        cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if len(cn) > 1:
            # probably not possible
            raise CertValidationException("Multiple CNs are not allowed")
        if len(cn) == 1:
            if "*" in cn[0].value:
                raise CertValidationException("Wildcard in CN is not allowed")
            if not validators.domain(cn[0].value):
                raise CertValidationException("CN is not a valid domain")

        try:
            san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

            # Check that the CN is inside the SAN as well
            if len(cn) == 1:
                dns_entries = san_extension.value.get_values_for_type(x509.DNSName) # type: ignore
                if cn[0].value not in dns_entries:  # type: ignore
                    raise CertValidationException("CN is not in SAN")
                if not validators.domain(cn[0].value):
                    raise CertValidationException("SAN is not a valid domain")

            # If no CN is given, check if the FIRST san entry is a valid domain
            if len(cn) == 0:
                # if we didn't have a common name, we ONLY check the first SAN entry
                first_entry = san_extension.value[0]        # type: ignore
                if not isinstance(first_entry, x509.DNSName):
                    raise CertValidationException("First SAN entry is not a DNSName")

                if not validators.domain(first_entry.value):
                    raise CertValidationException("First SAN entry is not a valid domain")
        except x509.ExtensionNotFound:
            # MUST have a SAN extension
            raise CertValidationException("No SAN extension found")

        # Check key usage
        try:
            extended_key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH not in extended_key_usage.value:    # type: ignore
                raise CertValidationException("No server authentication found in key usage")
            if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH not in extended_key_usage.value:    # type: ignore
                raise CertValidationException("No client authentication found in key usage")
        except x509.ExtensionNotFound:
            raise CertValidationException("No extended key usage found")

        return True


    @staticmethod
    def _detect_type(pem: bytes) -> CertAuthentication|None:
        """
        Get the certificate type (OV, EV, UZI) from the certificate. Note that this is a crude check and doesn't
        imply that the certificate is actually valid.
        """
        try:
            cert = x509.load_pem_x509_certificate(pem)
        except ValueError:
            return None

        try:
            cert_policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            for info in cert_policies.value: # type: ignore
                if info.policy_identifier == x509.ObjectIdentifier("2.23.140.1.2.2"):
                    return CertAuthentications.AUTH_OV_CERT
                if info.policy_identifier == x509.ObjectIdentifier("2.23.140.1.1"):
                    return CertAuthentications.AUTH_EV_CERT
                if info.policy_identifier == x509.ObjectIdentifier("2.16.528.1.1003.1.2.8.6"):
                    return CertAuthentications.AUTH_UZI_CERT
        except x509.ExtensionNotFound:
            pass

        return None
