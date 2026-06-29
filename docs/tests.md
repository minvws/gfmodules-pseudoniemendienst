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
      "alg": "RSA-OAEP-256",
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
      "extra_versions": {}
    }
  },
  "eval_subject": "Ngb5jRWtUc_EtfPud1uPnjhHwvww1pt51wx_DBao_Uc=",
  "final_pseudonym": "NN4uUzMPvmY7m7Mt8g5cLs_5G5ePCe_kgX1I16-ZJkA="
}
```

At this point, the `final_pseudonym` (`NN4uU...`) can be used by the receiver as the pseudonym for the personal ID `NL:bsn:950000012`.

The `subject` always holds the evaluation for the latest key version. The `extra_versions` claim is empty when only one key version is active; during key rotation it holds the older versions as `{"<version>": "<base64 eval>"}`, so a receiver can also finalize against an older key version.



# Steps to create reversible pseudonyms

### Create a JWE

Request:
```
POST /exchange/pseudonym
{
  "personalId": "NL:bsn:950000012",
  "recipientOrganization": "oin:00000099000000001000",
  "recipientScope": "bar",
  "pseudonymType": "irreversible"
}
```

Response:
```
eyJraWQiOiAiYXBjc3o....
```

Note: this is not an `application/json` content type, but an `Multipart/Encrypted`.

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
      "alg": "RSA-OAEP-256",
      "enc": "A256GCM",
      "cty": "application/json"
    },
    "decrypted": {
      "subject": "pseudonym:irreversible:gOm6ILU3e0jjB9TJIUUHo0O0CCCgbhmpDmnvauyGP2w=",
      "aud": "90000036",
      "scope": "bar",
      "version": "1.1",
      "iat": 1762770476,
      "exp": 1762770776
    }
  }
}

```




# Scenarios:

 org   | oin                      | max_key_usage 
-------|--------------------------|---------------
 Org 1 | oin:00000099000000001000 | irp           
 Org 2 | oin:00000098000000001000 | rp            
 Org 3 | oin:00000097000000001000 | bsn           

* Org 1 can only create irreversible pseudonyms. It cannot be decoded back to the personal ID by anyone.
* Org 2 can create reversible pseudonyms. It cannot decode itself back to the personal ID but can allow others (who have bsn max_key_usage) to do so.
* Org 3 can create reversible pseudonyms and can decode them back to the personal ID. They can receive reversible pseudonyms from others as well and decode them.
