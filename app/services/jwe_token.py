import json
import time
from typing import Any

from jwcrypto import jwe, jwk

from app.services.jwt_signer import JwtSigningService


class Jwe:
    """
    Builds the JWE that carries a pseudonym to its recipient. With signing
    keys the content is a JWT signed by the PRS (a nested JWT, RFC 7519
    §5.2), otherwise the plain JSON claims.
    """

    def __init__(self, signing: JwtSigningService | None = None) -> None:
        self.signing = signing

    def build(
        self,
        audience: str,
        scope: str,
        subject: str,
        pub_key: jwk.JWK,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        if extra_claims is None:
            extra_claims = {}
        now = int(time.time())
        claims = {
            "subject": subject,
            "aud": audience,
            "scope": scope,
            "version": "1.1",
            "iat": now,
            "exp": now + 300,
            **extra_claims,
        }

        if self.signing is None:
            plaintext = json.dumps(claims).encode("utf-8")
            content_type = "application/json"
        else:
            plaintext = self.signing.sign(claims).encode("ascii")
            content_type = "JWT"

        protected_headers = {
            "kid": pub_key.key_id,
            "alg": "RSA-OAEP",
            "enc": "A256GCM",
            "cty": content_type,
        }

        jwe_token = jwe.JWE(
            plaintext=plaintext,
            protected=json.dumps(protected_headers),
        )
        jwe_token.add_recipient(pub_key)
        return str(jwe_token.serialize(compact=True))
