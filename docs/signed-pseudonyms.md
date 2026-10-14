# Signed pseudonyms

Every pseudonym the PRS hands out travels in a JWE that is encrypted to the recipient's registered public key
(`/oprf/eval`, `/exchange/reversible-pseudonym`, `/exchange/irreversible-pseudonym`). The encryption makes sure only
the recipient can read the pseudonym. It does not prove that the PRS made it: anyone who knows the recipient's public
key can build a JWE for it.

With `enable_jwt_signing` set, the PRS therefore signs the claims first and encrypts the signed JWT: a nested JWT
(RFC 7519 §5.2), signed with PS256. The public keys are published at `GET /.well-known/jwks`, so a recipient can check
that a pseudonym was issued by the PRS and was not altered on the way.

## Token structure

```
JWE (compact)                       header: {"alg": "RSA-OAEP", "enc": "A256GCM", "kid": <recipient key>, "cty": "JWT"}
 └─ JWS (compact, the JWE plaintext) header: {"alg": "PS256", "kid": <PRS signing key>, "typ": "JWT"}
     └─ claims
```

The outer JWE is unchanged apart from `cty`: `JWT` for a signed token, `application/json` when signing is disabled and
the plaintext is the claims as JSON.

The inner JWS header:

| Header | Value                                                                              |
|--------|------------------------------------------------------------------------------------|
| `alg`  | Always `PS256`                                                                     |
| `kid`  | The RFC 7638 thumbprint of the signing key; selects the key in the JWKS            |
| `typ`  | `JWT`                                                                              |

The claims are the same as in an unsigned token, plus `iss`:

```json
{
  "subject": "pseudonym:irreversible:7w2lTA18UNm2VF7FH1GjttRIR8NT8ooqYegP2cT8Ff8=",
  "aud": "oin:00000003123456790000",
  "scope": "nvi",
  "version": "1.1",
  "iat": 1791977856,
  "exp": 1791978156,
  "keyVersion": 1,
  "iss": "https://pseudoniemendienst.example.nl"
}
```

| Claim           | Meaning                                                                                              |
|-----------------|------------------------------------------------------------------------------------------------------|
| `iss`           | The PRS, from `jwt_signing.issuer`. Set by the PRS last, so no other claim can override it          |
| `aud`           | The recipient organization, `oin:<20 digits>`                                                        |
| `scope`         | The recipient scope the token was made for                                                           |
| `subject`       | The pseudonym: `pseudonym:eval:`, `pseudonym:reversible:` or `pseudonym:irreversible:` plus the value |
| `iat`, `exp`    | Issued at and expiry; tokens are valid for five minutes                                              |
| `keyVersion`    | The recipient's key version the pseudonym was made with (exchange endpoints)                         |
| `extraVersions` | During a key rotation, the pseudonym or evaluation per older key version (see [endpoints.md](endpoints.md)) |

## Why PS256

- **RSA, because of the HSM.** Production keys live in the HSM, and the HSM API offers RSA-PSS signing over a digest
  the caller computes. The PRS hashes the JWS signing input itself and only sends the SHA-256 digest to the HSM.
- **PSS instead of PKCS#1 v1.5 (RS256).** RSA-PSS has a security proof and is the padding current guidance prefers
  for new RSA signatures. JOSE libraries support PS256 as widely as RS256.
- **Fixed parameters.** PS256 is RSA-PSS with SHA-256, MGF1 with SHA-256 and a 32 byte salt (RFC 7518 §3.5). The PRS
  uses exactly that, both with a local key and in the HSM.
- **Key size.** Signing keys must be RSA keys of at least 3072 bits; the PRS refuses to start with a smaller one.
- **One algorithm.** The PRS only signs with PS256, and recipients should accept nothing else (see below). There is no
  algorithm negotiation to get wrong.

## Verifying a pseudonym (for recipients)

A recipient configures two values once, out of band:

- the PRS issuer, e.g. `https://pseudoniemendienst.example.nl`, and
- the PRS JWKS URL, `<PRS base URL>/.well-known/jwks`.

Do not take the JWKS URL from the token; the `iss` claim is only compared with the configured issuer.

To accept a pseudonym:

1. Decrypt the JWE with your private key. Its `kid` header names the key you registered at the PRS.
2. Check that the JWE header `cty` is `JWT`. A token with `cty: application/json` is unsigned; reject it in every
   environment where signing is enabled.
3. Parse the plaintext as a compact JWS. Check that its `alg` is `PS256` and reject anything else, `none` in
   particular.
4. Look up the `kid` in the JWKS and verify the signature with that key. When the `kid` is not in your cached JWKS,
   fetch the JWKS again (at most once per minute or so) and retry once; a new key may have become active.
5. Check the claims: `iss` equals the configured issuer, `aud` equals your own OIN as `oin:<20 digits>`, and `exp` is
   in the future (allow a small clock skew, e.g. a minute).
6. Only then use `subject`.

### The JWKS

`GET /.well-known/jwks` is public and needs no authentication. It returns a JSON Web Key Set (RFC 7517) with every key
the PRS may have signed a still valid token with:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "8XnMgBBynigdp-ThfbpM_hIyitWL61KhaiZD_W5ib5w",
      "n": "s0cnsXqt3jVewh9J...",
      "e": "AQAB",
      "alg": "PS256",
      "use": "sig"
    }
  ]
}
```

The response carries `Cache-Control: public, max-age=900`. Cache it for up to 15 minutes; the rotation procedure below
counts on recipients picking up a new key within that time. The endpoint answers `404` when signing is disabled.

### Example

With [jwcrypto](https://jwcrypto.readthedocs.io/):

```python
import json
import time

import requests
from jwcrypto import jwe, jwk, jws

PRS_ISSUER = "https://pseudoniemendienst.example.nl"
PRS_JWKS_URL = "https://pseudoniemendienst.example.nl/.well-known/jwks"
OWN_OIN = "oin:00000003123456790000"
CLOCK_SKEW = 60


def verify_pseudonym(token: str, own_key: jwk.JWK, jwks: jwk.JWKSet) -> dict:
    outer = jwe.JWE()
    outer.deserialize(token, key=own_key)
    if outer.jose_header.get("cty") != "JWT":
        raise ValueError("pseudonym is not signed")

    inner = jws.JWS()
    inner.deserialize(outer.payload.decode("ascii"))
    header = inner.jose_header
    if header.get("alg") != "PS256":
        raise ValueError("unexpected signature algorithm")
    key = jwks.get_key(header["kid"])
    if key is None:
        raise ValueError("unknown kid, refresh the JWKS and retry once")
    inner.verify(key, alg="PS256")

    claims = json.loads(inner.payload)
    if claims["iss"] != PRS_ISSUER:
        raise ValueError("wrong issuer")
    if claims["aud"] != OWN_OIN:
        raise ValueError("not addressed to us")
    if claims["exp"] < time.time() - CLOCK_SKEW:
        raise ValueError("expired")
    return claims


jwks = jwk.JWKSet.from_json(requests.get(PRS_JWKS_URL, timeout=10).text)
```

In a test environment with `enable_test_routes`, `POST /test/oprf/receiver` and `POST /test/jwe/decode` show the inner
JWS header and whether the signature verifies (see [tests.md](tests.md)).

## Configuration

Signing is enabled with `enable_jwt_signing=True` in `[app]` and configured in `[jwt_signing]`:

```ini
[app]
enable_jwt_signing=True

[jwt_signing]
issuer=https://pseudoniemendienst.example.nl

# Keys in the HSM (production)
hsm_key_labels=prs-jwt-2026-10
active_key_label=prs-jwt-2026-10

# Or keys in PEM files (development)
# key_files=secrets/jwt-signing-1.pem
# active_key_file=secrets/jwt-signing-1.pem
```

- `key_files` and `hsm_key_labels` are comma separated lists. Every key in both lists is published in the JWKS.
- Exactly one of `active_key_file` and `active_key_label` is set; that key signs. It must be in its list.
- `hsm_key_labels` needs the HSM to be configured (`oprf.hsm_url`).
- Both lists may be used together, e.g. to move from a file key to an HSM key with the rotation below.

The PRS checks the configuration at startup and refuses to start when the issuer is missing, the active key is not in
its list, a key is not an RSA key of at least 3072 bits, an HSM label does not exist, or the same key is configured
twice.

### Creating a key

In the HSM, through the HSM API (as an administrator):

```shell
POST {hsm_url}/hsm/{module}/{slot}/generate/rsa
{"label": "prs-jwt-2026-10", "bits": 3072}
```

Any size of at least 3072 bits works; larger keys make signing slower.

The PRS reads the public key from the HSM at startup and signs through `/sign` with `RSA_PKCS_PSS`; the private key
never leaves the HSM.

As a file, for development:

```shell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out secrets/jwt-signing-1.pem
```

## Key rotation

Recipients cache the JWKS for up to 15 minutes and tokens live for five minutes. A new key must therefore be published
before it signs, and an old key must stay published until the last token it signed has expired. All PRS instances
must run with the same configuration at every step.

1. **Create** the new key (see above).
2. **Publish.** Add it to `hsm_key_labels` (or `key_files`) and leave the active key as it is. Deploy. The JWKS now
   lists both keys; the old one still signs.
3. **Wait at least 15 minutes** after the last instance has been deployed, so every recipient's cached JWKS holds the
   new key.
4. **Activate.** Set `active_key_label` (or `active_key_file`) to the new key. Deploy.
5. **Wait at least 20 minutes** after the last instance has been deployed: the five minute token lifetime plus the
   15 minute cache window, as a margin for recipients that verify a token some time after receiving it.
6. **Retire.** Remove the old key from the list. Deploy. Then destroy the old key in the HSM, or delete the file.

A recipient that follows step 4 of [verifying a pseudonym](#verifying-a-pseudonym-for-recipients) also copes with a
new key it has not seen yet, but the procedure does not depend on that.

### When a key is compromised

Skip the waiting: create a new key, make it the only key in the configuration, activate it, and deploy. Recipients
reject tokens signed with the new key until they refresh their JWKS, which they do on the unknown `kid`. Recipients
that cached the JWKS keep accepting the compromised key until their cache expires, at most 15 minutes. Inform the
recipients so they can flush their cache sooner.
