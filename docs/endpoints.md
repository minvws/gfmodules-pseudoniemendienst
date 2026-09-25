# PRS Endpoints

Previously when working with applications within gfmodules, the actual BSN number of a person was required to gain data. Now this data is pseudonymized by this service: instead of sharing a BSN, parties exchange pseudonyms that are scoped to a recipient organization.

This document lists the main service endpoints. The testing/helper endpoints (`/test/...`) are documented in [tests.md](tests.md), and the end-to-end OPRF evaluation flow is described in [oprf-eval-flow.md](oprf-eval-flow.md).

A recipient organization is always identified by a OIN in the form `oin:<20 digits>` (e.g. `oin:00000099000000001000`).

## Authentication and scopes

Every endpoint except the service information endpoints expects the `x-gf-*` headers set by the OIN-verifier proxy (see [trust-model.md](trust-model.md)). Requests without valid headers, or with an audience that is not in `authorization_headers.expected_audiences`, are rejected with `403`.

The `x-gf-scope` header carries the OAuth scopes of the caller's token. Each group of endpoints requires one scope:

| Endpoints          | Required scope        |
|--------------------|-----------------------|
| `/administration/*` | `prs:administration`  |
| `/oprf/eval`       | `prs:oprf-pseudonym`  |
| `/exchange/reversible-pseudonym` | `prs:pseudonym` |
| `/saml-exchange/*` | `prs:saml-pseudonym`  |
| `/test/*`          | none (headers still required) |

A request whose token lacks the required scope is rejected with `403`.

The calling organization (`x-gf-sub`) must also be registered in the PRS database. When it is not, the endpoint answers `403` with `Organization does not exist`. A registered organization that is not allowed to request the personal ID type an endpoint produces is refused with `403` as well, with `Not allowed to request personal_id_type: <type>`. The PRS never answers `401`: the OIN-verifier already authenticated the caller, so every refusal is an authorization decision.

## Service Information

Public, unauthenticated endpoints.

#### `GET /`
Service banner with the version and git reference from `version.json`, as plain text.

#### `GET /version.json`
The contents of `version.json`, or `404` when the file is absent.

#### `GET /health`
Health of the service and its components. Returns `200` when everything is healthy, `503` when a component is not:

```json
{
  "status": "ok",
  "components": {"database": "ok"}
}
```

## Administration Services

These endpoints are under `/administration` and require the `prs:administration` scope. They act on the calling organization only; the organization is taken from the verified headers, not from the request.

#### `POST /administration/keys`
Register a public key for one or more scopes (`domains`) of the calling organization. The PRS encrypts its OPRF responses for this organization to this key.

The key is supplied as a self-signed JWS in compact serialization. Its protected header carries the public key as a `jwk` with a `kid`, and its payload carries the calling organization's `oin` and an `iat`. The JWS must verify with the key in its own header, which proves possession of the private key.

```json
{
  "domains": ["bar"],
  "jws": "eyJhbGciOiJSUzI1NiIsImp3ayI6ey...."
}
```

`domains` is the list of recipient scopes the key applies to. A `*` entry is a wildcard and matches any scope that has no key of its own.

The JWS is rejected with `422` when it does not parse, the `jwk` is missing, contains private components or has no `kid`, the signature does not verify, `iat` or `oin` is missing, `iat` is more than one hour old, or `oin` differs from the calling organization.

Returns `201` with the stored key, `409` if one of the domains is already registered to another key of the organization.

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "domains": ["bar"],
  "jwk": {"kty": "RSA", "kid": "k1", "n": "...", "e": "AQAB"}
}
```

#### `GET /administration/keys`
List the registered public keys of the calling organization, in the same shape as above.

#### `PUT /administration/keys/{id}`
Replace the domains and the key of one registered key. The body is the same as for registration and the JWS is validated the same way.

```json
{
  "domains": ["bar", "baz"],
  "jws": "eyJhbGciOiJSUzI1NiIsImp3ayI6ey...."
}
```

Returns `200` with the updated key, `404` when the id does not exist for the calling organization, `409` when a domain is already registered to another key, `422` when the JWS is invalid.

#### `DELETE /administration/keys/{id}`
Delete one registered key. Returns `200` with `{"message": "key deleted"}`, or `404` when the id does not exist for the calling organization.

#### `POST /administration/key-versions`
Create a new HSM key version for the calling organization. Version numbers are assigned by the PRS, one higher than the organization's highest version. The OPRF secret for a version is generated in the HSM on first use.

```json
{
  "from_dt": "2026-01-01T00:00:00+00:00",
  "until_dt": "2027-01-01T00:00:00+01:00"
}
```

The body is optional. `from_dt` defaults to now and may lie in the past. `until_dt` must be later than now and later than `from_dt`. Both must include a timezone offset.

Returns `201`, or `409` when the organization has no key version yet to rotate from:

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "organization_id": "0d7a3d0e-1c9b-4d1e-9a6b-3e2f1c0d9b8a",
  "version": 2,
  "from_dt": "2026-01-01T00:00:00+00:00",
  "until_dt": "2027-01-01T00:00:00+01:00",
  "removed_at": null
}
```

#### `GET /administration/key-versions`
List all HSM key versions of the calling organization, including expired and removed ones, in the same shape as above.

#### `PUT /administration/key-versions/{id}`
Set or clear the end date of one key version. Once `until_dt` has passed, the version is no longer used for evaluation and the periodic cleanup (`python -m app.cleanup`) destroys its secret in the HSM and sets `removed_at`.

```json
{
  "until_dt": "2027-01-01T00:00:00+03:00"
}
```

`until_dt` must be later than now and include a timezone offset, or be `null` to clear the end date.

Returns `200` with the updated version, `404` when the id does not exist for the calling organization, `409` when the version has already been removed.

## OPRF Services

#### `POST /oprf/eval`
Evaluate a blinded personal identifier and return a JWE (encrypted to the recipient's public key) containing the OPRF evaluation. Requires the `prs:oprf-pseudonym` scope. See [oprf-eval-flow.md](oprf-eval-flow.md) for the full flow.

```json
{
  "encryptedPersonalId": "co1ZgSqfsiB8iEzmKWl3xgxlc0erstUNyBAC3tdjxzg=",
  "recipientOrganization": "oin:00000099000000001000",
  "recipientScope": "bar"
}
```

The calling organization must be allowed to request OPRF pseudonyms and the recipient organization must be allowed to receive them; both are administrative flags on the organization. The blind is evaluated against every HSM key version of the recipient that is active at that moment.

Response:

```json
{
  "jwe": "eyJraWQiOiAi...rest of JWE..."
}
```

The JWE is encrypted with `RSA-OAEP` and `A256GCM` to the recipient key registered for `recipientScope` (or the `*` wildcard key), and its `kid` header names that key. The decrypted payload carries the evaluation for the latest key version as `subject` in the form `pseudonym:eval:<base64>`, plus `aud` (the recipient), `scope`, `iat` and `exp` (five minutes). When multiple key versions are active (e.g. during key rotation), the older versions are included in an `extra_versions` claim (`{"<version>": "<base64 eval>"}`).

Errors: `403` when the calling organization may not request OPRF pseudonyms, `404` when the recipient organization is unknown, may not receive OPRF pseudonyms, has no key registered for the scope, or has no active HSM key version, `400` when the blind cannot be evaluated, `503` when the HSM cannot be reached.

## Exchange Services

#### `POST /exchange/reversible-pseudonym`
Exchange a personal ID for a reversible pseudonym bound to a recipient organization/scope. Requires the `prs:pseudonym` OAuth scope. The response is a JWE encrypted to the recipient's registered public key for that scope (content type `application/jwe`, status `201`); its decrypted `subject` claim is `pseudonym:reversible:<...>` and its `keyVersion` claim the recipient's HSM key version the pseudonym was made with. The pseudonym is deterministic for the same personal ID, organization, scope and key version, is computed with keys held in the HSM (see [component-crypto.md](component-crypto.md)), and can only be reversed to the personal ID by the PRS. When the HSM cannot be reached the endpoint returns `503`.

```json
{
  "personalId": "NL:bsn:950000012",
  "recipientOrganization": "oin:00000099000000001000",
  "recipientScope": "bar"
}
```

`personalId` is either `"<landCode>:<type>:<value>"` or an object `{"landCode": "NL", "type": "bsn", "value": "950000012"}`.

Before the personal ID is processed, two administrator-managed authorizations are checked (the "dubbele bevoegdheidscontrole" from the technical design, PRS-AK-DBAC):

- the calling organization (the verified `x-gf-sub` identity) must be allowed to *request* the `reversible_pseudonym` personal ID type;
- the recipient organization must be allowed to *receive* the `reversible_pseudonym` personal ID type, since the pseudonym can be reversed to the personal ID by the PRS.

Neither authorization can be set by the organizations themselves. Responses: `403` when the scope is missing, the calling organization is not registered, or it is not allowed to request reversible pseudonyms (the sender is checked first, so an unauthorized caller cannot probe which organizations exist), `404` when the recipient organization is unknown, not allowed to receive reversible pseudonyms, has no public key for the scope, or has no active HSM key version, `400` when `personalId` is malformed, has the wrong length, or fails the elfproef (the audit event records which, never the value).

Irreversible pseudonyms are not exchanged through this section: use `POST /oprf/eval`.

The former `/exchange/pseudonym`, `/exchange/rid` and `/receive` endpoints are not available.

## SAML Exchange Services

These routes are only mounted when `enable_saml_exchange_routes` is set

#### `POST /saml-exchange/reversible-pseudonym`
**Mock** of the [DigiD SAML exchange API](https://github.com/minvws/generiekefuncties-architectuur/blob/main/docs/prs/concepts/to/PRS-DOC-DRFT.md#digid-saml-exchange-api-prs-int-saml), available so the VAD/MGO can start integrating before the real implementation lands. It accepts any JSON body and forwards it to the internal [PRS-SAML service](https://github.com/minvws/gfmodules-prs-saml) (the SAML-ontvanger, configured via `saml_service.url`), which currently echoes it back unchanged; no SAML decryption or validation is performed and no pseudonym is derived. If the PRS-SAML service is unreachable the endpoint returns 502.

Requires the `prs:saml-pseudonym` OAuth scope: the OIN-verifier proxy validates the token and forwards its scopes in the `x-gf-scope` header, and the endpoint rejects requests without this scope (403).
