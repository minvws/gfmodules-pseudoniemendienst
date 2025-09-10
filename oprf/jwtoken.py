from jwcrypto import jwe, jwk
import json
import time
from typing import Any

_priv_jwk: jwk.JWK|None = None
_pub_jwk: jwk.JWK|None = None
_pub_kid: str|None = None


def get_public_key_kid() -> str:
    global _pub_kid

    if _pub_kid is None:
        key = get_public_key_pem()
        _pub_kid = key.thumbprint().rstrip("=")

    return _pub_kid


def get_public_key_pem() -> jwk.JWK:
   global _pub_jwk

   if _pub_jwk is None:
       with open("public.pem", "rb") as f:
           pub_key_pem = f.read()
           _pub_jwk = jwk.JWK.from_pem(pub_key_pem)

   return _pub_jwk


def get_private_key_pem() -> jwk.JWK:
   global _priv_jwk

   if _priv_jwk is None:
       with open("private.pem", "rb") as f:
           priv_key_pem = f.read()
           _priv_jwk = jwk.JWK.from_pem(priv_key_pem)

   return _priv_jwk


def decrypt_jwe(data: str) -> dict[str, Any] :
    try:
        token = jwe.JWE()
        token.deserialize(data)

        header = token.jose_header
        if header.get("alg") != "RSA-OAEP-256":
            raise ValueError("Invalid JWE algorithm")
        if header.get("enc") != "A256GCM":
            raise ValueError("Invalid JWE encryption")

        token.decrypt(get_private_key_pem())
        plaintext = token.payload.decode('utf-8')
        return json.loads(plaintext)
    except Exception as e:
        raise ValueError(f"Failed to decrypt JWE: {e}") from e


def build_jwe(aud: str, scope: str, subject: str) -> str:
    now = int(time.time())
    claims = {
        "subject": subject,
        "aud": aud,
        "scope": scope,
        "version": "1.1",
        "iat": now,
        "exp": now + 300,
    }

    protected_headers = {
        "kid": get_public_key_kid(),
        "alg": "RSA-OAEP-256",
        "enc": "A256GCM",
        "cty": "application/json",
    }

    jwe_token = jwe.JWE(
        plaintext=json.dumps(claims).encode("utf-8"),
        protected=json.dumps(protected_headers),
    )
    jwe_token.add_recipient(get_public_key_pem())
    return jwe_token.serialize(compact=True)
