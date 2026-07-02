# PRS Endpoints

Previously when working with applications within gfmodules, the actual BSN number of a person was required to gain data. Now this data is pseudonymized by this service: instead of sharing a BSN, parties exchange RIDs and pseudonyms that are scoped to a recipient organization.

This document lists the main service endpoints. The testing/helper endpoints (`/test/...`) are documented in [tests.md](tests.md), and the end-to-end OPRF evaluation flow is described in [oprf-eval-flow.md](oprf-eval-flow.md).

A recipient organization is always identified by a OIN in the form `oin:<20 digits>` (e.g. `oin:00000099000000001000`).

## Organizational Services

#### `POST /orgs`
Create a new organization.

```json
{
  "oin": "00000099000000001000",
  "name": "Example Organization",
  "max_key_usage": "irp"
}
```

`max_key_usage` is one of `bsn`, `rp`, or `irp` and caps which pseudonym types the organization may exchange.

#### `GET /org/{oin}`
Return the organization for the given OIN (digits only, e.g. `00000099000000001000`).

#### `PUT /org/{oin}`
Update an organization's `name` and `max_key_usage`.

#### `DELETE /org/{oin}`
Delete an organization (and its keys).

## Key Registration Services

These endpoints are protected by mutual TLS. The organization and its public key are derived from the client certificate, so they are not part of the request body.

In deployments this certificate should come from a trusted proxy and is exposed as
`x-forwarded-tls-client-cert`. For local testing, pass this header directly.

#### `POST /register/certificate`
Register the public key (taken from the mTLS client certificate) for one or more scopes of the calling organization.

```json
{
  "scope": ["bar"]
}
```

Returns `201` on success, `409` if a key for that organization/scope already exists.

#### `GET /keys/{oin}`
List the registered public keys for an organization.

#### `PUT /keys/{key_id}`
Update the scope/key data for a specific key.

#### `DELETE /keys/{key_id}`
Delete a specific key.

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
