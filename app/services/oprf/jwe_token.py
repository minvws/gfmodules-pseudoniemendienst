
from jwcrypto import jwe, jwk
import json
import time

class BlindJwe():

    @staticmethod
    def build(audience: str, scope: str, subject: str, pub_key: jwk.JWK, extra_claims: dict[str, str] = {}) -> str:
        """
        Build a JWT token
        """
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

        protected_headers = {
            "kid": pub_key.thumbprint(),
            "alg": "RSA-OAEP-256",
            "enc": "A256GCM",
            "cty": "application/json",
        }

        jwe_token = jwe.JWE(
            plaintext=json.dumps(claims).encode("utf-8"),
            protected=json.dumps(protected_headers),
        )
        jwe_token.add_recipient(pub_key)
        return str(jwe_token.serialize(compact=True))
