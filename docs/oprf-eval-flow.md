# OPRF evaluation flow (`POST /oprf/eval`)

This describes the internal PRS flow when a client asks the PRS to evaluate a
blinded personal identifier. The evaluation can run either against a local OPRF
key or, in production, against an HSM. When the HSM is used, the active key
versions are looked up from the `hsm_key_version` table (per OIN, for the current
date), the blind is evaluated against **every** active version, and the resulting
JWE stays backwards compatible: the `subject` always carries the latest version,
while older versions are added in a separate `extra_versions` claim.

Expired key versions are removed from the HSM by a separate scheduled program;
see [Expired HSM key cleanup](./hsm-key-cleanup.md).

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Router as OPRF Router<br/>(/oprf/eval)
    participant Org as OrgService
    participant Keys as KeyResolver
    participant OPRF as OprfService
    participant Ver as HsmKeyVersionService
    participant DB as Database
    participant HSM as HSM
    participant JWE as BlindJwe

    Client->>Router: POST /oprf/eval<br/>{encryptedPersonalId, recipientOrganization, recipientScope}

    Note over Router: recipientOrganization must start with "oin:"
    alt invalid prefix
        Router-->>Client: 400 Invalid recipient organization
    end

    Router->>Org: get_by_oin(oin)
    Org->>DB: SELECT organization WHERE oin = ?
    DB-->>Org: organization | none
    alt organization not found
        Org-->>Router: none
        Router-->>Client: 404 No organization found
    end
    Org-->>Router: organization

    Router->>Keys: resolve(org.id, recipientScope)
    Keys->>DB: SELECT organization_key WHERE org_id + scope
    DB-->>Keys: key_data | none
    alt public key not found
        Keys-->>Router: none
        Router-->>Client: 404 No public key for org/scope
    end
    Keys-->>Router: recipient public key (JWK)

    Router->>OPRF: eval_blind(req, pub_key)

    alt HSM configured (hsm_url set)
        OPRF->>Ver: get_active_versions(now)
        Ver->>DB: SELECT hsm_key_version<br/>not removed, from_dt <= now, until_dt null/>= now
        DB-->>Ver: active versions (all OINs)
        Ver-->>OPRF: active versions
        Note over OPRF: filter by OIN -> sorted version numbers<br/>(error if none active)
        loop for each active version v
            OPRF->>HSM: POST /oprf/evaluate<br/>label "oin-<org>-v<v>", blinded_point
            HSM-->>OPRF: result (eval bytes for v)
        end
    else local key
        OPRF->>OPRF: pyoprf.evaluate(server_key, blind)<br/>=> {1: eval bytes}
    end

    Note over OPRF: subject = "pseudonym:eval:" + base64(latest version eval)<br/>extra_versions = {version: base64(eval)} for older versions
    OPRF->>JWE: build(audience, scope, subject, pub_key,<br/>extra_claims={extra_versions})
    JWE-->>OPRF: compact JWE (encrypted to recipient)
    OPRF-->>Router: jwe string

    Router-->>Client: 200 {"jwe": "..."}
```
