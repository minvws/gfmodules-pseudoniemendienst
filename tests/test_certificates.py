import unittest
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from asn1crypto.core import IA5String
from cryptography import x509
from cryptography.hazmat._oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve

from app.services.tls_service import TLSService, CertValidationException

@dataclass
class CertOptions:
    ec_curve: EllipticCurve = field(default_factory=lambda: ec.SECP256R1())
    rsa_key_size: int = 2048
    san_othername_first: bool = False
    add_san: bool = True
    extended_key_usage: list[str] = field(default_factory=lambda: ["server", "client"])

def generate_cert(key_type: str, cn: str = "", san: list = [], options: CertOptions = CertOptions()) -> x509.Certificate:
    if key_type == "rsa":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=options.rsa_key_size,
        )
    elif key_type == "ec":
        private_key = ec.generate_private_key(options.ec_curve)
    elif key_type == "dsa":
        private_key = dsa.generate_private_key(key_size=2048)
    else:
        raise ValueError(f"Unknown key type: {key_type}")

    if cn == "":
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "myorg"),
        ])
    else:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "myorg"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])

    builder = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
    )

    if options.add_san:
        if options.san_othername_first:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.OtherName(ObjectIdentifier("2.5.5.5"), IA5String("foobar").dump()),
                    *[x509.DNSName(name) for name in san],
                ]),
                critical=False,
            )
        else:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in san]),
                critical=False,
            )

    key_usage_mapping = {
        "server": ExtendedKeyUsageOID.SERVER_AUTH,
        "client": ExtendedKeyUsageOID.CLIENT_AUTH,
        "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
        "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
        "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
        "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
    }

    if len(options.extended_key_usage) > 0:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([key_usage_mapping[usage] for usage in options.extended_key_usage if usage in key_usage_mapping]),
            critical=False,
        )

    return builder.sign(private_key, hashes.SHA256())



def get_tls_service():
    return TLSService("secp256r1,secp384r1,secp521r1", 2048)

class TestCerts(unittest.TestCase):
    def test_minimum_rsa_key(self) -> None:
        cert = generate_cert(
            key_type = "rsa",
            cn = "CN=foo.example.com",
            san = [],
            options = CertOptions(
                rsa_key_size = 1024,
            )
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "RSA key size is too small: 1024")

    def test_ec_curve(self) -> None:
        cert = generate_cert(
            key_type = "ec",
            cn = "foo.example.com",
            san = [],
            options = CertOptions(
                ec_curve = ec.BrainpoolP256R1(),
            )
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "Curve brainpoolP256r1 is not allowed")

    def test_invalid_keytype(self) -> None:
        cert = generate_cert(
            key_type = "dsa",
            cn = "foo.example.com",
            san = []
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "Invalid key type")

    def test_wildcard_cn(self) -> None:
        cert = generate_cert(
            key_type = "rsa",
            cn = "*.example.com",
            san = []
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "Wildcard in CN is not allowed")

    def test_ca_not_in_san(self) -> None:
        cert = generate_cert(
            key_type = "rsa",
            cn = "foo.example.com",
            san = [
                "bar.example.com",
                "baz.example.com",
                "*.example.com"
            ]
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "CN is not in SAN")

    def test_cn_not_present(self) -> None:
        cert = generate_cert(
            key_type = "rsa",
            cn = "",
            san = [
                "bar.example.org"
            ],
            options = CertOptions(
                san_othername_first= True
            )
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "First SAN entry is not a DNSName")

    def test_no_san(self) -> None:
        cert = generate_cert(
            key_type = "rsa",
            cn = "",
            san = [
                "bar.example.org"
            ],
            options = CertOptions(
                add_san = False
            )
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "No SAN extension found")


    def test_no_key_usage(self) -> None:
        cert = generate_cert(
            key_type = "rsa",
            cn = "",
            san = [
                "bar.example.org"
            ],
            options = CertOptions(
                extended_key_usage = []
            )
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "No extended key usage found")


    def test_client_key_usage(self) -> None:
        cert = generate_cert(
            key_type = "rsa",
            cn = "",
            san = [
                "bar.example.org"
            ],
            options = CertOptions(
                extended_key_usage = ["server"]
            )
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "No client authentication found in key usage")

    def test_server_key_usage(self) -> None:
        cert = generate_cert(
            key_type = "rsa",
            cn = "",
            san = [
                "bar.example.org"
            ],
            options = CertOptions(
                extended_key_usage = ["client"]
            )
        )

        service = get_tls_service()
        with self.assertRaises(CertValidationException) as context:
            service.validate_cert_elements(cert)
        self.assertEqual(str(context.exception), "No server authentication found in key usage")


    def test_too_much_key_usage_is_ok(self) -> None:
        cert = generate_cert(
            key_type = "rsa",
            cn = "",
            san = [
                "bar.example.org"
            ],
            options = CertOptions(
                extended_key_usage = ["client", "server", "code_signing"]
            )
        )

        service = get_tls_service()
        self.assertTrue(service.validate_cert_elements(cert))




