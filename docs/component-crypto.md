# Crypto


## RID

A RID consists of JSON data that contains a personal_id and recipient information.

    {
        "usage": <usage_scope>,
        "recipient_organization": <rcpt_org>,
        "recipient_scope": <rcpt_scope>,
        "personal_id": <personal_id>,
    }

A RID is encrypted with AES-256-GCM with the following properties:

    plaintext       JSON data
    key             hkdf(master_key, info=b"prs:rid", length=32)
    iv/nonce        12 bytes secure random
    mode            AES-GCM
    aad             b"RID:v1"
    layout          nonce || tag || ciphertext
    authentication  GCM tag included and verified on decryption
    
A RID is NOT deterministic.

Note that a RID is *ONLY* decryptable by the PRS service itself. It is not intended for decrypting by third party, 
but as an emphemeral token to transfer the personal_id to a another recipient.


## Reversible Pseudonym

The reversible pseudonym is an encrypted representation of the combination of:

    <personal_id> | <rcpt_org> | <rcpt_scope>

it is encrypted through AES-SIV, with the key derived as following:

    hkdf(master_key, info=b"prs:rp:aes-siv:" + <rcpt_org>, length=32) => <static_org_aes_key>

This allows the RP to be deterministic per organization, while still being irreversible without the master key.

A RP is encrypted with AES-SIV (AEAD) with the following proeperties:

    plaintext     <personal_id> | <rcpt_org> | <rcpt_scope>
    key           <org_static_aes_key>  
    aad           b"PRS:Pseudonym:v1"
    layout        tag || ciphertext
    
An RP is deterministic and only reversible by the PRS service using the organization key derived from the master key.


## Irreversible Pseudonym

The irreversible pseudonym is a hashed representation of the combination of:

    <personal_id> | <rcpt_org> | <rcpt_scope>

it is hashed through:

    hmac_sha256(<static_hmac_key>, subject) => pseudonym

where the static_hmac_key is derived as following:

    hkdf(master_key, info=b"prs:irp:hmac", length=32) => <static_hmac_key>

An IRP is deterministic.
