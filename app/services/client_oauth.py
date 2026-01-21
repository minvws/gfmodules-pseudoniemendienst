import base64
import hashlib
import hmac
import logging
import ssl
from typing import Any, Dict, List

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, Request
from jwt import PyJWKClient

from app.config import ConfigClientOAuth
from app.models.ura import UraNumber

SSL_CLIENT_CERT_HEADER_NAME = "x-forwarded-tls-client-cert"  # "x-proxy-ssl_client_cert"

logger = logging.getLogger(__name__)


class ClientOAuthService:
    """
    Client OAuth2 service for verifying tokens and mTLS binding
    """

    def __init__(self, config: ConfigClientOAuth) -> None:
        self.config = config
        if config.enabled:
            self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create an SSL context for mTLS connections to the JWKS endpoint.
        """
        if (
            self.config.mtls_cert is None
            or self.config.mtls_key is None
            or self.config.verify_ca is None
        ):
            raise ValueError(
                "mTLS certificate and key must be provided for Client OAuth2"
            )

        context = ssl.create_default_context()
        if isinstance(self.config.verify_ca, bool) and self.config.verify_ca is True:
            context.verify_mode = ssl.CERT_REQUIRED

        context.load_cert_chain(
            certfile=self.config.mtls_cert, keyfile=self.config.mtls_key
        )
        if isinstance(self.config.verify_ca, str):
            context.load_verify_locations(cafile=self.config.verify_ca)

        return context

    def enabled(self) -> bool:
        """
        Check if client OAuth2 is enabled.
        """
        return self.config.enabled

    def override_ura_number(self) -> UraNumber:
        """
        Get the override URA number when OAuth2 is disabled.
        """
        return UraNumber(self.config.override_ura_number)

    def verify(self, request: Request) -> Dict[str, Any]:
        """
        Verify an incoming OAuth2 token from the Authorization header.
        """
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.lower().startswith("bearer "):
            raise HTTPException(
                status_code=401, detail="Missing or invalid Authorization header"
            )

        token = auth_header[7:]  # Remove "Bearer "
        claims = self._verify_token(token)
        self._verify_mtls(request, claims)

        return claims

    def _verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify JWT token and return claims.
        """
        jwk_client = PyJWKClient(
            self.config.jwks_url, cache_keys=True, ssl_context=self._ssl_context
        )
        signing_key = jwk_client.get_signing_key_from_jwt(token).key

        try:
            claims = jwt.decode(
                token,
                signing_key,
                leeway=30,
                algorithms=["RS256"],
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={
                    "require": ["exp", "iat", "sub", "aud", "iss", "scope", "cnf"],
                },
            )

        except Exception as e:
            logger.debug("Failed to decode JWT: %s", e)
            raise HTTPException(status_code=401, detail="Invalid token")

        return claims  # type: ignore

    @staticmethod
    def _verify_mtls(request: Request, claims: Dict[str, Any]) -> None:
        """
        Verify mTLS binding by checking cnf.x5t#S256 against presented client certificate thumbprint.
        """

        certs = ClientOAuthService.get_pem_from_request(request)
        if not certs:
            logger.error("Client certificate not presented or verification failed")
            raise HTTPException(
                status_code=401,
                detail="Client certificate not presented or verification failed",
            )

        # Calculate thumbprint of presented client certificate, ignoring the chain
        presented_cert = x509.load_pem_x509_certificate(certs[0].encode())
        cert_der = presented_cert.public_bytes(serialization.Encoding.DER)
        sha256_hash = hashlib.sha256(cert_der).digest()
        request_cert_fp = base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode()

        # Compare with cnf.x5t#S256 in token claims
        cnf = claims.get("cnf")
        if cnf is None:
            fp = None
        elif isinstance(cnf, dict):
            fp = cnf.get("x5t#S256")
        else:
            fp = None

        if fp is None:
            logger.debug("mTLS binding failed")
            raise HTTPException(status_code=401, detail="Invalid token")

        if not hmac.compare_digest(fp, request_cert_fp):
            logger.debug("mTLS binding failed")
            raise HTTPException(status_code=401, detail="Invalid token")

    @staticmethod
    def get_pem_from_request(request: Request) -> List[str]:
        """
        Extracts and returns the PEM-encoded client certificate from the request headers.
        """
        if (
            SSL_CLIENT_CERT_HEADER_NAME not in request.headers
            or not request.headers.get(SSL_CLIENT_CERT_HEADER_NAME)
        ):
            logger.debug("Client certificate not found or verification failed.")
            return []

        certs = request.headers.get(SSL_CLIENT_CERT_HEADER_NAME, "").split(",")
        return [
            ClientOAuthService.fixup_cert_headers_and_footers(cert) for cert in certs
        ]

    @staticmethod
    def fixup_cert_headers_and_footers(cert: str) -> str:
        # Add PEM headers/footers if missing
        if not cert.startswith("-----BEGIN CERTIFICATE-----"):
            cert = (
                "-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----"
            )

        # If we are by any chance missing newlines after/before the headers, add them
        if not cert.startswith("-----BEGIN CERTIFICATE-----\n"):
            cert = cert.replace(
                "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n"
            )
            cert = cert.replace(
                "-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----"
            )
        return cert
