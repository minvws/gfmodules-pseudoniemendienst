# Steps To Create A Deterministic Pseudonym Using OPRF

### Create a oprf input as a client

Request:
```
POST /test/oprf/client
{
  "personalId": "NL:bsn:950000012"
}
```

Response:
```
{
  "blinded_input": "co1ZgSqfsiB8iEzmKWl3xgxlc0erstUNyBAC3tdjxzg=",
  "blind_factor": "vFNWIVPKey18sMi81ZnO68aExoxVe_ruaStee9If1QI="
}
```

#### Evaluate the input by the pseudoniemendienst

Request:
```
POST /oprf/eval
{
  "encryptedPersonalId": "co1ZgSqfsiB8iEzmKWl3xgxlc0erstUNyBAC3tdjxzg=",
  "recipientOrganization": "oin:00000099000000001000",
  "recipientScope": "bar"
}
```

Response:
```
{
  "jwe": "eyJraWQiOiAi...rest of JWE... "
}
```


### Send the JWE plus blind factor to the receiver

Request:
```
POST /test/oprf/receiver
{
  "blind_factor": "vFNWIVPKey18sMi81ZnO68aExoxVe_ruaStee9If1QI=",
  "jwe": "eyJraWQiOiAi...rest of JWE... ",
  "priv_key_pem": "-----BEGIN PRIVATE KEY-----MIIG/....-----END PRIVATE KEY-----"
}
```

Response:
```
{
  "jwe_data": "eyJraWQiOi...rest of JWE... ",
  "priv_key_pem": "-----BEGIN PRIVATE KEY-----MIIG/gI....-----END PRIVATE KEY-----",
  "priv_key_kid": "apcsz4HE6UYny5RiSh6aEIp7N_Cb2EGStknChLJTuug",
  "blind_factor": "vFNWIVPKey18sMi81ZnO68aExoxVe_ruaStee9If1QI=",
  "jwe": {
    "headers": {
      "kid": "apcsz4HE6UYny5RiSh6aEIp7N_Cb2EGStknChLJTuug",
      "alg": "RSA-OAEP",
      "enc": "A256GCM",
      "cty": "application/json"
    },
    "decrypted": {
      "subject": "pseudonym:eval:Ngb5jRWtUc_EtfPud1uPnjhHwvww1pt51wx_DBao_Uc=",
      "aud": "oin:00000099000000001000",
      "scope": "bar",
      "version": "1.1",
      "iat": 1762769767,
      "exp": 1762770067,
      "extraVersions": {}
    }
  },
  "eval_subject": "Ngb5jRWtUc_EtfPud1uPnjhHwvww1pt51wx_DBao_Uc=",
  "final_pseudonym": "NN4uUzMPvmY7m7Mt8g5cLs_5G5ePCe_kgX1I16-ZJkA="
}
```

At this point, the `final_pseudonym` (`NN4uU...`) can be used by the receiver as the pseudonym for the personal ID `NL:bsn:950000012`.

The `subject` always holds the evaluation for the latest key version. The `extraVersions` claim is empty when only one key version is active; during key rotation it holds the older versions as `{"<version>": "<base64 eval>"}`, so a receiver can also finalize against an older key version.



# Steps to create reversible pseudonyms

The calling organization (the `x-gf-sub` identity) must be allowed to request the `reversible_pseudonym` personal ID type, and the recipient organization must be allowed to receive it; see the scenarios below.

### Create a JWE

Request:
```
POST /exchange/reversible-pseudonym
{
  "personalId": "NL:bsn:950000012",
  "recipientOrganization": "oin:00000098000000001000",
  "recipientScope": "bar"
}
```

Response:
```
eyJraWQiOiAiYXBjc3o....
```

The response has status `201` and content type `application/jwe`.

Basically, this is all you need. You can send this JWE to the receiver, who can decrypt it using their private key to obtain the pseudonym.

To test:

Request:
```
POST /test/jwe/decode
{
  "jwe": "eyJ....",
  "priv_key_pem": "-----BEGIN PRIVATE KEY-----MI....."
}
```

Response:
```
{
  "jwe_data": "eyJraWQi....",
  "priv_key_pem": "-----BEGIN PRIVATE KEY-----MIIG....-----END PRIVATE KEY-----",
  "priv_key_kid": "apcsz4HE6UYny5RiSh6aEIp7N_Cb2EGStknChLJTuug",
  "jwe": {
    "headers": {
      "kid": "apcsz4HE6UYny5RiSh6aEIp7N_Cb2EGStknChLJTuug",
      "alg": "RSA-OAEP",
      "enc": "A256GCM",
      "cty": "application/json"
    },
    "decrypted": {
      "subject": "pseudonym:reversible:gOm6ILU3e0jjB9TJIUUHo0O0CCCgbhmpDmnvauyGP2w=",
      "aud": "oin:00000098000000001000",
      "scope": "bar",
      "version": "1.1",
      "iat": 1762770476,
      "exp": 1762770776
    }
  }
}

```




# Steps to exchange a reversible pseudonym for a personal ID

Use the reversible pseudonym obtained above by Org 2 (`00000098000000001000`). Send the trusted development headers
with Org 2 as `x-gf-sub` and `prs:pseudonym` in `x-gf-scope`. Org 2 must have both `reversible_pseudonym` request and
receive grants. Use its public key already registered for `bar` (or `*`). The required `recipientOrganization` must
also identify Org 2. Enable `enable_exchange_services_routes` to mount the endpoint.

Request:

```text
POST /exchange/personal-id
{
  "reversiblePseudonym": "pseudonym:reversible:gOm6ILU3e0jjB9TJIUUHo0O0CCCgbhmpDmnvauyGP2w=",
  "recipientOrganization": "oin:00000098000000001000",
  "recipientScope": "bar"
}
```

The bare pseudonym value is also accepted. This example uses `bar` for both the source and destination scope.
Another destination scope is allowed when Org 2 has a public key registered for it or a wildcard key.
The response has status `201`, content type `application/jwe`, and a compact JWE body:

```text
eyJraWQiOiAi...rest of JWE...
```

For a local test, call `POST /test/jwe/decode` as above, using Org 2's private key.
The decrypted payload is:

```json
{
  "subject": "NL:bsn:950000012",
  "aud": "oin:00000098000000001000",
  "scope": "bar",
  "version": "1.1",
  "iat": 1762770476,
  "exp": 1762770776
}
```

The canonical personal ID is in `subject`, and the token expires after 300 seconds. Neither `keyVersion` nor
`extraVersions` is included. Changing `recipientOrganization` to Org 3 returns `403` with `Unauthorized request`
before organisation/key lookup or reversal. With Org 3 as the verified caller, a pseudonym issued to Org 2 cannot be
reversed. The encryption key, `aud` and success audit `doel_oin` derive from `x-gf-sub`; an acting client named in
`x-gf-act-sub` does not change the recipient. The source HSM key version must not be removed and
must satisfy `from_dt <= now` and either no `until_dt` or `now < until_dt`. An older version still reverses the
pseudonym during this grace period when a newer version is current. At `until_dt`, reversal returns `410`
(`Pseudonym key version no longer available`), even before physical HSM cleanup. Missing, not yet active, and
removed source versions return the same `410`.

The success APP audit event retains the source HSM version as integer `sleutel_versie` and records the caller
JWK's `kid` as `ontvanger_pubkey_id`, matching the JWE protected header. The success SIEM event remains OIN-only.

# Scenarios:

 org   | oin                      | may request           | may receive
-------|--------------------------|-----------------------|-----------------------------
 Org 1 | oin:00000099000000001000 | oprf                  | oprf
 Org 2 | oin:00000098000000001000 | reversible_pseudonym  | reversible_pseudonym
 Org 3 | oin:00000097000000001000 | reversible_pseudonym  | oprf, reversible_pseudonym

* Org 1 may not hand a personal ID to the PRS and can only receive irreversible pseudonyms (through the OPRF). Those cannot be decoded back to the personal ID by anyone.
* Org 2 can hand a personal ID to the PRS and receive reversible pseudonyms.
* Org 3 can hand a personal ID to the PRS and receive both OPRF evaluations and reversible pseudonyms.

An exchange of a personal ID for a reversible pseudonym therefore succeeds from Org 2 or Org 3 towards Org 2 or Org 3, and is refused when Org 1 is the sender (403) or the recipient (404). The same request and receive grants govern `/exchange/personal-id`, but both must belong to the verified caller: Org 2 can exchange its own reversible pseudonym for a personal ID encrypted to Org 2, and Org 3 can do the same for itself. A different `recipientOrganization` returns `403`.
