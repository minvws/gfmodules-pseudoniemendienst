from cryptography import x509
from cryptography.x509 import Certificate


def load_cert(path: str) -> list[Certificate]:
    with open(path, "rb") as bf:
        data = bf.read()
        cert = x509.load_pem_x509_certificates(data)

    return cert
