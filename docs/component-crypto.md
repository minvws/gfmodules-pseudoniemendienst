# Crypto


## RID

A RID consists of JSON data that contains personal and recipient information.

    {
        "usage": <usage_scope>,
        "recipient_organization": <rcpt_org>,
        "recipient_scope": <rcpt_scope>,
        "personal_id": <personal_id>,
    }

A RID is encrypted with AES with the following properties:

    IV = <random_bytes>
    AES(key(=<static_aes_key>, mode=GCM, iv=IV)

data is padded through PKCS7.

A RID is NOT deterministic.

Note that a RID is *ONLY* decryptable by the PRS service itself.


## Reversible Pseudonym

The reversible pseudonym is an encrypted representation of the combination of:

    <personal_id> | <rcpt_org> | <rcpt_scope>

it is encrypted through AES with the following properties:

    IV = sha256(<rcpt_org>)[:16]
    AES(key=<org_static_aes_key>, mode=GCM, iv=IV)

data is padded through PKCS7.

An RP is deterministic.


## Irreversible Pseudonym

The irreversible pseudonym is a hashed representation of the combination of:

    <personal_id> | <rcpt_org> | <rcpt_scope>

it is hashed through:

    hmac_sha256(<static_hmac_key>, subject) => pseudonym

An IRP is deterministic.
