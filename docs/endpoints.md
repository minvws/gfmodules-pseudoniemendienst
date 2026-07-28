# PRS Endpoints

Previously when working with applications within gfmodules, the actual BSN number of a person was required to gain data. Now this data is pseudonymized by this service: instead of sharing a BSN, parties exchange RIDs and pseudonyms that are scoped to a recipient organization.

This document lists the main service endpoints. The testing/helper endpoints (`/test/...`) are documented in [tests.md](tests.md), and the end-to-end OPRF evaluation flow is described in [oprf-eval-flow.md](oprf-eval-flow.md).

A recipient organization is always identified by a OIN in the form `oin:<20 digits>` (e.g. `oin:00000099000000001000`).

## Administration Services

These endpoints are under `/administration` and require OAuth authorization. `POST /administration/register/certificate` additionally uses mTLS: the public key is taken from the caller's TLS client certificate.

#### `POST /administration/register/certificate`
Register the public key (taken from the mTLS client certificate) for one or more scopes of the calling organization.

```json
{
  "scope": ["bar"],
  "key_id": "k1"
}
```

`scope` must contain at least one entry. A `*` scope is a wildcard and matches all recipient scopes.

`scope` values are normalized to lowercase and deduplicated.

`key_id` is optional. It is included as the `kid` header in the `/oprf/eval` JWE response.

Returns `201` on success, `409` if a key for that organization/scope already exists.

#### `GET /administration/keys`
List the registered public keys for the authenticated organization.

```json
[
  {
    "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "scope": ["bar"],
    "key_data": "-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----\\n",
    "key_id": "k1"
  }
]
```

#### `PUT /administration/keys/{id}`
Update the scope/key data for a specific key. Include `key_id` to change the key identifier; set it to `null` (or omit it) to clear it.

```json
{
  "scope": ["bar", "baz"],
  "key_id": "k2",
  "key_data": "-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----\\n"
}
```

#### `DELETE /administration/keys/{id}`
Delete a specific key.

#### `POST /administration/key-versions`
Create a new HSM key version for the authenticated organization.

```json
{
  "from_dt": "2026-01-01T00:00:00+00:00",
  "until_dt": "2027-01-01T00:00:00+01:00"
}
```

`from_dt` and `until_dt` are optional when omitted; when provided they must include a timezone offset.

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "version": 1,
  "from_dt": "2026-01-01T00:00:00+00:00",
  "until_dt": "2027-01-01T00:00:00+01:00",
  "removed": false
}
```

Returns `201` on success.

#### `GET /administration/key-versions`
List all HSM key versions for the authenticated organization.

#### `PUT /administration/key-versions/{id}`
Update the end date for one key version.

```json
{
  "until_dt": "2027-01-01T00:00:00+03:00"
}
```

`until_dt` may also be set to `null` to clear the existing end date.

## Exchange Services

#### `POST /exchange/pseudonym`
Exchange a personal ID for a pseudonym targeted at a recipient organization/scope. The response is a JWE encrypted to the recipient's registered public key (content type `application/jwe`, status `201`).

```json
{
  "personalId": "NL:bsn:950000012",
  "recipientOrganization": "oin:00000099000000001000",
  "recipientScope": "bar",
  "pseudonymType": "irreversible"
}
```

`pseudonymType` is `irreversible` or `reversible`. The decrypted JWE `subject` is `pseudonym:irreversible:<...>` or `pseudonym:reversible:<...>`.

#### `POST /exchange/rid`
Exchange a personal ID for a RID that the recipient can later redeem. The RID is wrapped in a JWE (content type `application/jwe`, status `201`) and carries a `ridUsage` claim.

```json
{
  "personalId": "NL:bsn:950000012",
  "recipientOrganization": "oin:00000099000000001000",
  "recipientScope": "bar",
  "ridUsage": "irp"
}
```

#### `POST /receive`
Redeem a previously issued RID for a pseudonym (or the BSN, when allowed). The requested `pseudonymType` must be permitted both by the RID's usage and by the recipient organization's `max_key_usage`.

```json
{
  "rid": "rid:<encrypted-rid>",
  "recipientOrganization": "oin:00000099000000001000",
  "recipientScope": "bar",
  "pseudonymType": "irp"
}
```

`pseudonymType` is one of `rp`, `irp`, or `bsn`. Response:

```json
{
  "pseudonym": "pseudonym:irreversible:<...>",
  "type": "irp"
}
```

## OPRF Services

#### `POST /oprf/eval`
Evaluate a blinded personal identifier and return a JWE (encrypted to the recipient's public key) containing the OPRF evaluation. See [oprf-eval-flow.md](oprf-eval-flow.md) for the full flow.

```json
{
  "encryptedPersonalId": "co1ZgSqfsiB8iEzmKWl3xgxlc0erstUNyBAC3tdjxzg=",
  "recipientOrganization": "oin:00000099000000001000",
  "recipientScope": "bar"
}
```

Response:

```json
{
  "jwe": "eyJraWQiOiAi...rest of JWE..."
}
```

The decrypted JWE `subject` carries the evaluation for the latest key version in the form `pseudonym:eval:<base64>`. When multiple key versions are active (e.g. during key rotation), the older versions are included in an `extra_versions` claim (`{"<version>": "<base64 eval>"}`).
