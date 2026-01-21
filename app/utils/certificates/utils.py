import logging
import textwrap



logger = logging.getLogger(__name__)

_CERT_START = "-----BEGIN CERTIFICATE-----"
_CERT_END = "-----END CERTIFICATE-----"

def enforce_cert_newlines(cert_data: str) -> str:
    cert_data = cert_data.split(_CERT_START)[-1].split(_CERT_END)[0].strip()
    result = _CERT_START
    result += "\n"
    result += "\n".join(textwrap.wrap(cert_data.replace(" ", ""), 64))
    result += "\n"
    result += _CERT_END

    return result
