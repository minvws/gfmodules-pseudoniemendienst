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

The reversible pseudonym follows the Double-HMAC-IV construction of the technical design (PRS-AK-F0XF). It is an
encryption of the subject

    <personal_id> | oin:<rcpt_org> | <rcpt_scope>

under keys that belong to the recipient organization and a key version. Per (organization, version) two keys exist,
an AES-256 key and an HMAC key. In production they live in the HSM under the labels

    oin-<oin>-rp-v<version>-aes
    oin-<oin>-rp-v<version>-hmac

and are created on first use. Without an HSM (development only) they are derived from the master key:

    hkdf(master_key, info=b"prs:rp:aes:<oin>:v<version>", length=32)   => <aes_key>
    hkdf(master_key, info=b"prs:rp:hmac:<oin>:v<version>", length=32)  => <hmac_key>

The design describes one shared "versie_secret"; a PKCS#11 generic secret cannot double as an AES key, so the two
roles are separate objects (which also resolves open question PRS-VR-P15Y on key reuse).

The pseudonym is computed as:

    iv          hmac_sha256(<hmac_key>, hmac_sha256(<hmac_key>, subject))[:16]
    ciphertext  aes_256_cbc(<aes_key>, iv, pkcs7(subject))
    layout      format (1 byte, 0x01) || version (2 bytes, big endian) || ciphertext || iv

The double HMAC makes the IV deterministic without letting anyone who later obtains the HMAC key link an IV back to
a personal ID. HMAC-SHA256 yields 32 bytes; the AES block size fixes the IV at the first 16.

The key version is the organization's active HSM key version at the time of creation (the latest one when several
are active during rotation) and is carried in the pseudonym so the PRS can select the right key when reversing.

Reversal decrypts the ciphertext with the (organization, version) AES key, recomputes the IV from the decrypted
subject and compares it, in constant time, with the embedded IV. A mismatch, a subject naming another organization, or
a version that has been destroyed is rejected. Reversal is only possible by the PRS itself.

An RP is deterministic per (personal_id, organization, scope, version).


## Irreversible Pseudonym

The irreversible pseudonym is a hashed representation of the combination of:

    <personal_id> | <rcpt_org> | <rcpt_scope>

it is hashed through:

    hmac_sha256(<static_hmac_key>, subject) => pseudonym

where the static_hmac_key is derived as following:

    hkdf(master_key, info=b"prs:irp:hmac", length=32) => <static_hmac_key>

An IRP is deterministic.
