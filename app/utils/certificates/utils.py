import base64
import logging
import textwrap
from pathlib import Path
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.data import AllowedFilesExtenions
from app.utils.certificates.exceptions import CertificateLoadingError

logger = logging.getLogger(__name__)

_CERT_START = "-----BEGIN CERTIFICATE-----"
_CERT_END = "-----END CERTIFICATE-----"


def load_one_certificate_file(path: str) -> str:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found at: {file_path}")

    with open(file_path, "r") as file:
        try:
            cert_data = file.read()
        except IsADirectoryError as e:
            logger.warning("Error occurred while reading file")
            raise e

    return cert_data


def load_many_certificate_files(dir: str, allowed_extensions: List[AllowedFilesExtenions]) -> List[str]:
    file_path = Path(dir)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found at: {file_path}")

    cert_files = []
    for file in file_path.iterdir():
        file_extension = str(file).split(".")[-1]

        if file_extension in [e.value for e in allowed_extensions]:
            certificate_file = load_one_certificate_file(str(file))
            cert_files.append(certificate_file)

    return cert_files


def create_certificate(cert: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(cert.encode())
    except ValueError as e:
        raise CertificateLoadingError(f"Unable to create CA certificate from path certificate with error {e}")


def load_certificate(cert_path: str) -> x509.Certificate:
    """Load and parse CA certificate from file path."""
    cert_str = load_one_certificate_file(cert_path)
    return create_certificate(cert_str)


def enforce_cert_newlines(cert_data: str) -> str:
    cert_data = cert_data.split(_CERT_START)[-1].split(_CERT_END)[0].strip()
    result = _CERT_START
    result += "\n"
    result += "\n".join(textwrap.wrap(cert_data.replace(" ", ""), 64))
    result += "\n"
    result += _CERT_END

    return result


def get_x5t_from_certificate(certificate: x509.Certificate) -> str:
    sha1_fingerprint = certificate.fingerprint(hashes.SHA512())
    x5t = base64.urlsafe_b64encode(sha1_fingerprint).decode("utf-8")
    x5t = x5t.rstrip("=")  # Remove padding for x5t

    return x5t
